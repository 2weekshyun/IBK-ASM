#!/usr/bin/env python3
# portable_asm_scan_then_screenshot_then_ssh.py
# Flow:
# 1) Port scan for all IPs (CIDR from scan_ip.txt)
# 2) For every OPEN port -> screenshot attempt (http://, https://)
# 3) For every OPEN port -> SSH attempt with all credentials
# Result: reports/{ip}.txt + screenshots/{ip}_{port}.png
# 내부 점검용 전제. 반드시 허가된 네트워크에서만 사용.

import os
import sys
import time
import json
import socket
import ipaddress
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== Optional 라이브러리 =====
try:
    import paramiko
    PARAMIKO = True
except Exception:
    PARAMIKO = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    SELENIUM = True
except Exception:
    SELENIUM = False

try:
    from webdriver_manager.chrome import ChromeDriverManager
    WEBDRIVER_MANAGER = True
except Exception:
    WEBDRIVER_MANAGER = False

try:
    from tqdm import tqdm
    TQDM = True
except Exception:
    TQDM = False

# ===== 기본 설정 =====
SCAN_LIST = "scan_ip.txt"
CREDENTIALS_FILE = "credentials.json"
REPORT_DIR = "reports"
SCREENSHOT_DIR = "screenshots"

DEFAULT_PORT_RANGE = (1, 65535)   # 필요시 --ports로 1-63335 지정
CONNECT_TIMEOUT = 2.0
MAX_WORKERS = 200
BANNER_BYTES = 512
SSH_CHECK_COMMAND = "uname -a; id"

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


def print_intro():
    banner = r"""
============================================================
               PORTABLE ASM  |  BLUE TEAM EDITION
------------------------------------------------------------
   Internal Attack Surface Diagnostic Scanner
   Version - 1.0 (Test)
============================================================
"""
    print(banner)



# ===== 유틸 =====
def expand_targets(path):
    """
    scan_ip.txt에서 타겟 IP 리스트 생성
    - CIDR (예: 10.0.0.0/24)  -> 네트워크 호스트 전부
    - 단일 IP (예: 10.0.0.5)  -> 해당 IP만
    - '#' 뒤에 오는 내용은 주석으로 무시
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")

    ips = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue

            # 라인 끝에 주석이 붙어 있으면 제거
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            if not line:
                continue

            try:
                # CIDR인지 단일 IP인지 분기
                if "/" in line:
                    # CIDR -> 네트워크 전체 호스트
                    net = ipaddress.ip_network(line, strict=False)
                    hosts = list(net.hosts())
                    if not hosts:
                        print(f"[!] line {lineno}: {line} -> no usable hosts", file=sys.stderr)
                        continue
                    ips.extend(str(h) for h in hosts)
                else:
                    # 단일 IP
                    ipaddress.ip_address(line)  # 유효성 체크
                    ips.append(line)
            except Exception as e:
                print(f"[!] line {lineno}: invalid target '{raw.strip()}': {e}", file=sys.stderr)

    uniq = sorted(set(ips))
    print(f"[i] expanded {len(uniq)} unique IPs from {path.name}")
    return uniq


def all_private(ips):
    for ip in ips:
        a = ipaddress.ip_address(ip)
        if not (a.is_private or a.is_loopback or a.is_link_local):
            return False, ip
    return True, None


def chunk_ports(range_tuple):
    s, e = range_tuple
    if s < 1:
        s = 1
    if e > 65535:
        e = 65535
    return list(range(s, e + 1))


# ===== 포트 스캔 =====
def sync_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        banner = ""
        try:
            s.settimeout(0.8)
            data = s.recv(BANNER_BYTES)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        finally:
            try:
                s.close()
            except:
                pass
        return port, True, banner or "open"
    except Exception as e:
        try:
            s.close()
        except:
            pass
        return port, False, str(e)


# ===== credentials 로드 =====
def load_creds():
    if not os.path.exists(CREDENTIALS_FILE):
        return []
    try:
        data = json.load(open(CREDENTIALS_FILE, "r", encoding="utf-8"))
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return data
    except Exception as e:
        print("[!] Failed to parse credentials.json:", e, file=sys.stderr)
    return []


# ===== chromedriver 경로 결정 =====
def _resolve_chromedriver_path():
    # exe 옆 chromedriver.exe 우선
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.getcwd()
    local = os.path.join(base, "chromedriver.exe")
    if os.path.exists(local):
        return local
    # 없으면 webdriver-manager 사용
    if WEBDRIVER_MANAGER:
        try:
            return ChromeDriverManager().install()
        except Exception:
            return None
    return None


# ===== 스크린샷 작업 =====
def take_screenshot_task(ip, port, timeout=12):
    """
    한 포트에 대해 http / https 둘 다 시도해서 스크린샷 찍기
    - http://ip:port/  → 시도
    - https://ip:port/ → 시도
    인증서 오류(ERR_CERT_AUTHORITY_INVALID 등)는 크롬 옵션으로 무시
    리턴: (ip, port, ok_bool, info_str, any_image_path)
          ok_bool: 둘 중 하나라도 성공하면 True
          any_image_path: 마지막으로 성공한 이미지 경로 (없으면 None)
    """
    if not SELENIUM:
        return (ip, port, False, "selenium not installed", None)

    cdp = _resolve_chromedriver_path()
    if not cdp:
        return (ip, port, False, "chromedriver not found / webdriver-manager failed", None)

    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1366,768")
    opts.add_argument("--hide-scrollbars")

    # 🔥 인증서 오류(자체 서명, 사설 CA 등) 무시
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--allow-insecure-localhost")
    opts.add_argument("--ignore-ssl-errors=yes")

    try:
        service = Service(cdp)
        driver = webdriver.Chrome(service=service, options=opts)
    except Exception as e:
        return (ip, port, False, f"chrome init error: {e}", None)

    results = []
    any_ok = False
    any_path = None

    # http / https 둘 다 시도
    for scheme in ("http", "https"):
        url = f"{scheme}://{ip}:{port}/"
        out = os.path.join(SCREENSHOT_DIR, f"{ip}_{port}_{scheme}.png")
        try:
            driver.set_page_load_timeout(timeout)
            driver.get(url)
            time.sleep(1)
            driver.save_screenshot(out)
            results.append(f"{scheme.upper()}: OK -> {out}")
            any_ok = True
            any_path = out
        except Exception as e:
            # 실패해도 그냥 계속 진행
            results.append(f"{scheme.upper()}: FAIL -> {e}")

    try:
        driver.quit()
    except:
        pass

    info = " | ".join(results)
    return (ip, port, any_ok, info, any_path)


# ===== SSH 작업 =====
def ssh_check_task(ip, port, cred):
    """IP/Port/credential 조합에 대해 SSH 시도. (성공/실패 전부 기록)
       Return (ip, port, cred_label, ok, info)"""
    if not PARAMIKO:
        return (ip, port, cred.get("name", "?"), False, "paramiko not installed")
    username = cred.get("username")
    password = cred.get("password")
    pkey = cred.get("pkey")
    ssh_port = cred.get("port", port)  # cred에 port 있으면 cred 우선
    label = cred.get("name") or f"{username}@{ssh_port}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if pkey:
            key = paramiko.RSAKey.from_private_key_file(pkey)
            client.connect(ip, port=ssh_port, username=username, pkey=key, timeout=8)
        else:
            client.connect(ip, port=ssh_port, username=username, password=password, timeout=8)
        stdin, stdout, stderr = client.exec_command(SSH_CHECK_COMMAND, timeout=10)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        info = f"stdout:\n{out}\nstderr:\n{err}"
        return (ip, ssh_port, label, True, info)
    except Exception as e:
        return (ip, ssh_port, label, False, str(e))
    finally:
        try:
            client.close()
        except:
            pass


# ===== 리포트 저장 =====
def save_report(ip, ports_list, screenshots_done, ssh_results):
    """
    ports_list: list of (port,banner)
    screenshots_done: list of (port, ok, info, path)
    ssh_results: list of (port, label, ok, info)
    """
    lines = []
    lines.append(f"Report for {ip}")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    if not ports_list:
        lines.append("No open ports found.")
    else:
        lines.append("Open ports:")
        for p, b in sorted(ports_list, key=lambda x: x[0]):
            lines.append(f" - {p}: {b}")
    lines.append("")

    if screenshots_done:
        lines.append("Screenshots (per open port):")
        for p, ok, info, path in sorted(screenshots_done, key=lambda x: x[0]):
            if ok:
                lines.append(f" - {p}: OK -> {path} ({info})")
            else:
                lines.append(f" - {p}: FAIL -> {info}")
    else:
        lines.append("Screenshots: none")
    lines.append("")

    if ssh_results:
        lines.append("SSH attempts (all open ports):")
        for p, label, ok, info in ssh_results:
            lines.append(f" - port {p}, cred={label}, OK={ok}")
            lines.append(f"   {info}")
    else:
        lines.append("SSH attempts: none")

    fn = os.path.join(REPORT_DIR, f"{ip}.txt")
    with open(fn, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return fn


# ===== CLI 파서 =====
def parse_args():
    ap = argparse.ArgumentParser(description="Scan -> ALL screenshots -> ALL SSH attempts on open ports")
    ap.add_argument("--allow-public", action="store_true", help="Allow scanning public IPs (dangerous).")
    ap.add_argument("--ports", type=str, default=f"{DEFAULT_PORT_RANGE[0]}-{DEFAULT_PORT_RANGE[1]}",
                    help="Port range like 1-1024 or 1-63335")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS, help="Max concurrent workers")
    ap.add_argument("--no-screenshots", action="store_true", help="Disable screenshot phase")
    ap.add_argument("--no-ssh", action="store_true", help="Disable SSH phase")
    ap.add_argument("--no-progress", action="store_true", help="Disable tqdm progress bars")
    return ap.parse_args()


def main():
    args = parse_args()
    workers = max(1, args.workers)

    if not os.path.exists(SCAN_LIST):
        print(f"[!] {SCAN_LIST} not found. Create it with CIDR lines (e.g. 10.0.0.0/24).")
        sys.exit(1)

    try:
        ips = expand_targets(SCAN_LIST)
    except Exception as e:
        print("[!] failed to expand CIDRs:", e, file=sys.stderr)
        sys.exit(1)
    if not ips:
        print("[!] no IPs found in", SCAN_LIST, file=sys.stderr)
        sys.exit(1)

    if not args.allow_public:
        ok, bad = all_private(ips)
        if not ok:
            print(f"[!] Aborting: non-private IP detected: {bad}. Use --allow-public to override (dangerous).",
                  file=sys.stderr)
            sys.exit(1)

    pr = args.ports.split("-", 1)
    try:
        pstart = int(pr[0])
        pend = int(pr[1])
    except Exception:
        print("[!] Invalid --ports format. Use like 1-1024 or 1-63335", file=sys.stderr)
        sys.exit(1)
    ports_to_scan = chunk_ports((pstart, pend))

    print(f"[i] IPs to scan: {len(ips)}")
    print(f"[i] Ports per IP: {ports_to_scan[0]}..{ports_to_scan[-1]} (total {len(ports_to_scan)})")
    print(f"[i] Workers: {workers}")

    creds = load_creds()
    if creds:
        print(f"[i] credentials.json loaded ({len(creds)} entries).")
    else:
        print("[i] No credentials.json found; SSH phase will be limited/empty.")

    show_progress = (not args.no_progress) and TQDM

    # ========== PHASE 1: PORT SCAN ==========
    print("\n=== PHASE 1: PORT SCAN ===")
    scan_results = {}  # ip -> list of (port,banner)
    overall_pbar = tqdm(total=len(ips), desc="IPs", unit="ip") if show_progress else None

    for ip in ips:
        open_ports = []
        if show_progress:
            pbar = tqdm(total=len(ports_to_scan), desc=f"scan:{ip}", unit="port", leave=False)
        else:
            pbar = None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(sync_connect, ip, p, CONNECT_TIMEOUT): p for p in ports_to_scan}
            for fut in as_completed(futures):
                try:
                    port, ok, info = fut.result()
                except Exception as e:
                    port, ok, info = futures[fut], False, str(e)
                if ok:
                    open_ports.append((port, info))
                if pbar:
                    pbar.set_postfix_str(f"open:{len(open_ports)}")
                    pbar.update(1)

        if pbar:
            pbar.close()

        scan_results[ip] = sorted(open_ports, key=lambda x: x[0])
        print(f"[i] {ip}: found {len(open_ports)} open ports")
        if overall_pbar:
            overall_pbar.update(1)

    if overall_pbar:
        overall_pbar.close()

    # ========== PHASE 2: ALL OPEN PORT SCREENSHOTS ==========
    print("\n=== PHASE 2: SCREENSHOTS FOR ALL OPEN PORTS ===")
    screenshots_results_by_ip = {}  # ip -> list of (port, ok, info, path)

    screenshot_tasks = []
    for ip, ports in scan_results.items():
        for p, _ in ports:
            screenshot_tasks.append((ip, p))
    print(f"[i] Screenshot tasks: {len(screenshot_tasks)}")

    if not args.no_screenshots and screenshot_tasks:
        show_ss_progress = (not args.no_progress) and TQDM
        ss_pbar = tqdm(total=len(screenshot_tasks), desc="Screenshots", unit="task") if show_ss_progress else None
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(take_screenshot_task, ip, p): (ip, p) for (ip, p) in screenshot_tasks}
            for fut in as_completed(futures):
                ip, p = futures[fut]
                try:
                    ipr, prt, ok, info, path = fut.result()
                except Exception as e:
                    ipr, prt, ok, info, path = ip, p, False, str(e), None
                screenshots_results_by_ip.setdefault(ipr, []).append((prt, ok, info, path))
                if ss_pbar:
                    ss_pbar.update(1)
        if ss_pbar:
            ss_pbar.close()
    else:
        if args.no_screenshots:
            print("[i] Screenshots disabled by flag.")
        else:
            print("[i] No open ports for screenshots.")

    # ========== PHASE 3: SSH ATTEMPTS ON ALL OPEN PORTS ==========
    print("\n=== PHASE 3: SSH ATTEMPTS ON ALL OPEN PORTS ===")
    ssh_results_by_ip = {}  # ip -> list of (port, label, ok, info)

    if not args.no_ssh and creds:
        ssh_tasks = []
        # 🔥 모든 열린 포트에 대해, 모든 credential로 SSH 시도
        for ip, ports in scan_results.items():
            for p, banner in ports:
                for cred in creds:
                    ssh_tasks.append((ip, p, cred))

        print(f"[i] SSH tasks (all open ports x creds): {len(ssh_tasks)}")

        show_ssh_progress = (not args.no_progress) and TQDM
        ssh_pbar = tqdm(total=len(ssh_tasks), desc="SSH", unit="try") if show_ssh_progress else None
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ssh_tasks)))) as ex:
            futures = {ex.submit(ssh_check_task, ip, p, cred): (ip, p, cred) for (ip, p, cred) in ssh_tasks}
            for fut in as_completed(futures):
                try:
                    ipr, ssh_port, label, ok, info = fut.result()
                except Exception as e:
                    ip, p, cred = futures[fut]
                    ipr, ssh_port, label, ok, info = ip, p, cred.get("name", "?"), False, str(e)
                ssh_results_by_ip.setdefault(ipr, []).append((ssh_port, label, ok, info))
                if ssh_pbar:
                    ssh_pbar.update(1)
        if ssh_pbar:
            ssh_pbar.close()
    else:
        if args.no_ssh:
            print("[i] SSH phase disabled by flag.")
        else:
            print("[i] No credentials.json -> SSH phase skipped.")

    # ========== 리포트 작성 ==========
    print("\n=== FINAL: Writing Reports ===")
    for ip in scan_results.keys():
        ports = scan_results.get(ip, [])
        ss_done = screenshots_results_by_ip.get(ip, [])
        ssh_res = ssh_results_by_ip.get(ip, [])
        rpt = save_report(ip, ports, ss_done, ssh_res)
        print(f"[+] report saved: {rpt}")

    print("\n[*] All phases complete.")


if __name__ == "__main__":
    print_intro()
    main()
