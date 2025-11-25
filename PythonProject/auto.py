import os
import socket
import requests
import json
import logging
import time
import ipaddress
from datetime import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
from concurrent.futures import ProcessPoolExecutor, as_completed

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

import paramiko

from PIL import Image, ImageDraw, ImageFont

# =====================
# 네트워크/대역 설정 (단일 IP + CIDR 혼용 가능)
# =====================
NETWORKS = []

# 203.227.232.69 ~ 203.227.232.255 → 그 다음
# for i in range(68, 256):
#     NETWORKS.append(f"203.227.232.{i}")
#
# # 114.52.78.28 ~ 114.52.78.255 → 맨 앞
# for i in range(28, 256):
#     NETWORKS.append(f"114.52.78.{i}")

# 마지막에 CIDR 대역 추가
#NETWORKS += [
#    "203.235.68.0/24",
#    "183.110.221.0/24"
# ]

# "203.227.232.0/24",
# "114.52.78.63/24", <-- 63부터 11/7
NETWORKS += [
    "203.227.232.0/24",
    "114.52.78.0/24",
    "203.235.68.0/24",
    "183.110.221.0/24",
    "27.96.156.213",
    "27.96.157.170",
    "27.96.157.194",
    "27.96.156.169",
    "175.45.214.94",
    "211.188.34.29"
]

# CIDR → IP 풀기
TARGET_IPS = []
for net in NETWORKS:
    if "/" in net:
        network = ipaddress.ip_network(net, strict=False)
        TARGET_IPS.extend([str(ip) for ip in network.hosts()])
    else:
        TARGET_IPS.append(net)

print(f"[INFO] 스캔 대상 IP 개수: {len(TARGET_IPS)}")

# =====================
# 일반 설정
# =====================
WELL_KNOWN_PORTS = range(1, 65535)                # 1~65535
USER_AGENT = "ibk-blue"

OPENCTI_API_URL = "http://127.0.0.1:8080/graphql"
OPENCTI_API_KEY = "1a54db41-fa8a-4b0a-bbae-67793140ea75"

MAX_PROCESSES = 50

# 아티팩트(스크린샷) 저장/노출
ARTIFACT_DIR = "./artifacts"
ARTIFACT_BASE_URL = "http://127.0.0.1:8000/artifacts"  # python -m http.server 8000 으로 제공

# SSH 접속 계정 (IP별 계정/비번 또는 키)
SSH_CREDENTIALS = {
    # "192.168.0.2": {"username": "root", "password": "pass"},
    # "114.52.78.10": {"username": "ubuntu", "pkey_path": "/home/me/.ssh/id_rsa", "passphrase": None},
}

# 옵션: 웹/SSH 캡처 on/off
ENABLE_WEB_SHOTS = True
ENABLE_SSH_SHOTS = True

# =====================
# 로깅
# =====================
logging.basicConfig(
    filename='./network_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def checkpoint(msg: str):
    print(f"[CHK] {msg}")
    logging.info(f"[CHK] {msg}")

# =====================
# 공통 유틸
# =====================
def _headers():
    return {
        "Authorization": f"Bearer {OPENCTI_API_KEY}",
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def _gql_error(payload):
    return ("errors" in payload) and bool(payload["errors"])

def ensure_artifact_dir():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)

def safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".", "+") else "_" for c in name)

# =====================
# OpenCTI: Marking / Label / ExternalRef
# =====================
_TLP_GREEN_ID_CACHE = None

def get_marking_id(tlp_label="TLP:GREEN"):
    global _TLP_GREEN_ID_CACHE
    if _TLP_GREEN_ID_CACHE is not None and tlp_label == "TLP:GREEN":
        return _TLP_GREEN_ID_CACHE

    q = {
        "query": """
        query MarkingDefinitions($search: String) {
          markingDefinitions(search: $search, first: 10) {
            edges { node { id definition } }
          }
        }
        """,
        "variables": {"search": tlp_label}
    }
    try:
        r = requests.post(OPENCTI_API_URL, headers=_headers(), json=q, timeout=10)
        r.raise_for_status()
        data = r.json()
        if _gql_error(data):
            print(f"[OpenCTI 마킹 조회 오류] {data['errors']}")
            return None

        edges = data.get("data", {}).get("markingDefinitions", {}).get("edges", [])
        for e in edges:
            node = e.get("node", {})
            if node.get("definition") == tlp_label:
                _TLP_GREEN_ID_CACHE = node.get("id")
                return _TLP_GREEN_ID_CACHE
        print(f"[OpenCTI] '{tlp_label}' 마킹을 찾지 못했습니다.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[OpenCTI 마킹 조회 연결 오류] {e}")
        return None

def upsert_label(label_value):
    q = {
        "query": """
        mutation LabelAdd($input: LabelAddInput!) {
          labelAdd(input: $input) { id value }
        }
        """,
        "variables": {"input": {"value": label_value}}
    }
    r = requests.post(OPENCTI_API_URL, headers=_headers(), json=q, timeout=10)
    r.raise_for_status()
    j = r.json()
    if _gql_error(j):
        raise RuntimeError(j["errors"])
    return j["data"]["labelAdd"]["id"]

def create_external_reference(source_name: str, url: str, description: str = "") -> str:
    q = {
        "query": """
        mutation ExtRefAdd($input: ExternalReferenceAddInput!) {
          externalReferenceAdd(input: $input) { id source_name url }
        }
        """,
        "variables": {"input": {"source_name": source_name, "url": url, "description": description}}
    }
    r = requests.post(OPENCTI_API_URL, headers=_headers(), json=q, timeout=10)
    r.raise_for_status()
    j = r.json()
    if _gql_error(j):
        raise RuntimeError(j["errors"])
    return j["data"]["externalReferenceAdd"]["id"]

# =====================
# OpenCTI: IPv4 Observable
# =====================
def upsert_ipv4_observable(ip):
    attempts = [
        {
            "name": "input",
            "query": """
                mutation AddObs($type: String!, $input: StixCyberObservableAddInput!) {
                  stixCyberObservableAdd(type: $type, input: $input) { id observable_value }
                }
            """,
            "variables": lambda ip: {"type": "IPv4-Addr", "input": {"value": ip}},
        },
        {
            "name": "value",
            "query": """
                mutation AddObs($type: String!, $value: String!) {
                  stixCyberObservableAdd(type: $type, value: $value) { id observable_value }
                }
            """,
            "variables": lambda ip: {"type": "IPv4-Addr", "value": ip},
        },
        {
            "name": "observable",
            "query": """
                mutation AddObs($type: String!, $observable: StixCyberObservableAddInput!) {
                  stixCyberObservableAdd(type: $type, observable: $observable) { id observable_value }
                }
            """,
            "variables": lambda ip: {"type": "IPv4-Addr", "observable": {"value": ip}},
        },
    ]

    last_error = None
    for sig in attempts:
        for retry in range(3):
            try:
                payload = {"query": sig["query"], "variables": sig["variables"](ip)}
                r = requests.post(OPENCTI_API_URL, headers=_headers(), json=payload, timeout=20)
                if r.status_code >= 500:
                    last_error = f"HTTP {r.status_code}: {r.text[:200]}"
                    time.sleep(2 ** retry)
                    continue
                r.raise_for_status()
                j = r.json()
                if "errors" in j and j["errors"]:
                    last_error = f"{sig['name']} signature GraphQL errors: {j['errors']}"
                    break
                node = j.get("data", {}).get("stixCyberObservableAdd", {})
                oid = node.get("id")
                if oid:
                    return oid
                last_error = f"{sig['name']} signature: no id in response"
                break
            except requests.exceptions.RequestException as e:
                last_error = f"{sig['name']} signature request error: {e}"
                time.sleep(2 ** retry)
                continue

    raise RuntimeError(f"IPv4 observable create failed. last_error={last_error}")

# =====================
# 웹 스크린샷 (Selenium / webdriver-manager)
# =====================
def make_chrome():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1280,720")
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument(f"user-agent={USER_AGENT}")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(10)
    driver.set_script_timeout(10)
    return driver

def web_screenshots(ip: str) -> list:
    ensure_artifact_dir()
    results = []
    if not ENABLE_WEB_SHOTS:
        return results

    checkpoint(f"웹 스크린샷 시작: {ip}")
    try:
        driver = make_chrome()
    except Exception as e:
        print(f"[웹 드라이버 오류] {e}")
        return results

    targets = [("http", f"http://{ip}/"), ("https", f"https://{ip}/")]
    for scheme, url in targets:
        try:
            driver.get(url)
            title = driver.title or f"{scheme}://{ip}"
            fname = safe_filename(f"{ip}_{scheme}.png")
            path = os.path.join(ARTIFACT_DIR, fname)
            driver.save_screenshot(path)
            print(f"[웹 스샷] {url} -> {path}")
            results.append({"title": title, "filename": fname, "url": f"{ARTIFACT_BASE_URL}/{fname}"})
        except Exception as e:
            print(f"[웹 접속 실패] {url}: {e}")

    try:
        driver.quit()
    except Exception:
        pass

    checkpoint(f"웹 스크린샷 종료: {ip}, 생성 {len(results)}개")
    return results

# =====================
# SSH 세션 캡처
# =====================
def ssh_session_capture(ip: str, commands=None, timeout=6) -> str:
    creds = SSH_CREDENTIALS.get(ip)
    if not creds:
        return read_ssh_banner(ip)

    username = creds.get("username")
    password = creds.get("password")
    pkey_path = creds.get("pkey_path")
    passphrase = creds.get("passphrase")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if pkey_path:
            pkey = paramiko.RSAKey.from_private_key_file(pkey_path, password=passphrase)
            client.connect(ip, port=22, username=username, pkey=pkey, timeout=timeout)
        else:
            client.connect(ip, port=22, username=username, password=password, timeout=timeout)

        output = []
        cmds = commands or ["uname -a", "whoami", "uptime"]
        for cmd in cmds:
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="ignore")
            err = stderr.read().decode("utf-8", errors="ignore")
            output.append(f"$ {cmd}\n{out}{err}")
        return "\n".join(output).strip()
    except Exception as e:
        return f"(SSH session failed: {e})"
    finally:
        try:
            client.close()
        except Exception:
            pass

def read_ssh_banner(ip: str, port: int = 22, timeout: float = 4.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(256)
            return banner.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        return f"(SSH banner read failed: {e})"

def render_text_to_png(text: str, outfile: str, width: int = 1200, padding: int = 20):
    ensure_artifact_dir()
    font = ImageFont.load_default()
    lines = text.splitlines() or [text]
    tmp = Image.new("RGB", (width, 10))
    draw = ImageDraw.Draw(tmp)
    line_height = max(font.getbbox("A")[3], 14) + 6

    max_w = max([int(draw.textlength(ln, font=font)) for ln in lines]) if lines else 0
    img_w = min(width, max_w + padding * 2)
    img_h = padding * 2 + line_height * len(lines)

    img = Image.new("RGB", (img_w or 400, img_h or 120), color=(16, 16, 16))
    draw = ImageDraw.Draw(img)
    y = padding
    for ln in lines:
        draw.text((padding, y), ln, font=font, fill=(230, 230, 230))
        y += line_height

    img.save(outfile)
    print(f"[SSH 세션 스샷] {outfile}")

def ssh_cli_screenshot(ip: str) -> dict | None:
    if not ENABLE_SSH_SHOTS:
        return None
    checkpoint(f"SSH 세션 캡처 시작: {ip}")
    session_text = ssh_session_capture(ip)
    if not session_text:
        checkpoint(f"SSH 세션 없음: {ip}")
        return None
    fname = safe_filename(f"{ip}_ssh.png")
    outpath = os.path.join(ARTIFACT_DIR, fname)
    render_text_to_png(f"{ip}:22\n\n{session_text}", outpath)
    checkpoint(f"SSH 세션 캡처 종료: {ip}")
    return {"title": "SSH session", "filename": fname, "url": f"{ARTIFACT_BASE_URL}/{fname}"}

# =====================
# Report 생성
# =====================
def register_to_opencti(ip, ports, ext_refs: list[dict]):
    print(f"[OpenCTI] {ip} 스캔 결과를 OpenCTI에 등록 중...")
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    tlp_green_id = get_marking_id("TLP:GREEN")
    object_marking = [tlp_green_id] if tlp_green_id else []

    # IP Observable
    ip_obs_id = None
    try:
        ip_obs_id = upsert_ipv4_observable(ip)
    except Exception as e:
        print(f"[경고] IP Observable 생성 실패: {e}")

    # 포트 라벨
    label_ids = []
    for port in ports:
        try:
            lid = upsert_label(str(port))
            label_ids.append(lid)
        except Exception as e:
            print(f"[경고] Label({port}) 생성 실패: {e}")

    # External References
    ext_ref_ids = []
    for ref in ext_refs:
        try:
            xid = create_external_reference(
                source_name=f"screenshot:{ref.get('title') or 'web/ssh'}",
                url=ref["url"],
                description=f"{ip} - {ref.get('title')}"
            )
            ext_ref_ids.append(xid)
        except Exception as e:
            print(f"[경고] ExternalReference 생성 실패({ref.get('url')}): {e}")

    # description에 이미지 URL 포함
    img_links_block = ""
    if ext_refs:
        lines = [f"- {ref['title']}: {ref['url']}" for ref in ext_refs]
        img_links_block = "\n\nImages:\n" + "\n".join(lines)

    description_text = f"Well-known ports open on {ip}: {ports}{img_links_block}"

    mutation = {
        "query": """
        mutation ReportCreate($input: ReportAddInput!) {
          reportAdd(input: $input) { id name created published }
        }
        """,
        "variables": {
            "input": {
                "name": f"IBK-ASM Result for {ip}",
                "description": description_text,
                "published": now,
                "confidence": 80,
                "report_types": ["network-scan"],
                "objectMarking": object_marking,
                "objects": [ip_obs_id] if ip_obs_id else [],
                "objectLabel": label_ids if label_ids else [],
                "externalReferences": ext_ref_ids if ext_ref_ids else []
            }
        }
    }

    try:
        response = requests.post(OPENCTI_API_URL, headers=_headers(), json=mutation, timeout=20)
        response.raise_for_status()
        payload = response.json()
        if _gql_error(payload):
            msg = f"[OpenCTI 등록 실패 - GraphQL errors] {json.dumps(payload['errors'], ensure_ascii=False)}"
            print(msg); logging.error(msg); return
        report = payload.get("data", {}).get("reportAdd")
        if not report:
            msg = f"[OpenCTI 등록 실패 - reportAdd 없음] 응답: {json.dumps(payload, ensure_ascii=False)}"
            print(msg); logging.error(msg); return
        msg = f"[OpenCTI 등록 성공] {ip} -> {ports}, report_id={report.get('id')}"
        print(msg); logging.info(msg)
    except requests.exceptions.RequestException as e:
        msg = f"[OpenCTI 연결/응답 오류] {e}"
        print(msg); logging.error(msg)

# =====================
# 포트 스캔 (멀티프로세싱)
# =====================
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except Exception:
        return None

def scan_host(ip):
    print(f"[SCAN] {ip}에 대해 포트 스캐닝 시작...")
    open_ports = []
    total_ports = len(WELL_KNOWN_PORTS)
    with ProcessPoolExecutor(max_workers=MAX_PROCESSES) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in WELL_KNOWN_PORTS}
        for idx, future in enumerate(as_completed(futures), start=1):
            port = futures[future]
            result = future.result()
            if result:
                open_ports.append(result)
                print(f"  [+] {ip}:{result} -> OPEN")
            else:
                print(f"  [SCAN] {ip}:{port} -> CLOSED")
            if idx % 50 == 0 or idx == total_ports:
                percent = (idx / total_ports) * 100
                print(f"  [진행률] {ip} {idx}/{total_ports} ({percent:.2f}%) 완료")
    open_ports.sort()
    print(f"[SCAN] {ip} 스캔 완료. 열린 포트: {open_ports if open_ports else '없음'}")
    return open_ports

# =====================
# 메인 작업
# =====================
def run_scan():
    print("\n==============================")
    print(f"[{datetime.now()}] 네트워크 스캔 시작")
    logging.info("==== 네트워크 스캔 시작 ====")

    ensure_artifact_dir()

    for ip in TARGET_IPS:
        ext_refs = []
        open_ports = scan_host(ip)

        # 웹 스크린샷
        if ENABLE_WEB_SHOTS and (80 in open_ports or 443 in open_ports):
            checkpoint(f"웹 스크린샷 준비: {ip}")
            web_refs = web_screenshots(ip)
            ext_refs.extend(web_refs)

        # SSH CLI 스샷
        if ENABLE_SSH_SHOTS and 22 in open_ports:
            ssh_ref = ssh_cli_screenshot(ip)
            if ssh_ref:
                ext_refs.append(ssh_ref)

        if open_ports:
            msg = f"[+] {ip} 열린 포트: {open_ports}"
            print(msg); logging.info(msg)
            checkpoint(f"OpenCTI 등록 시작: {ip}")
            register_to_opencti(ip, open_ports, ext_refs)
            checkpoint(f"OpenCTI 등록 종료: {ip}")
        else:
            msg = f"[-] {ip} 열린 포트 없음"
            print(msg); logging.info(msg)

    logging.info("==== 네트워크 스캔 종료 ====")
    print(f"[{datetime.now()}] 네트워크 스캔 종료")
    print("==============================\n")

# =====================
# 스케줄러
# =====================
if __name__ == "__main__":
    scheduler = BlockingScheduler()
    scheduler.add_job(run_scan, 'interval', hours=1, next_run_time=datetime.now())
    print("[스케줄러 시작] 1시간 단위로 스캔 작업을 실행합니다.")
    logging.info("스케줄러 시작: 1시간 단위 실행")
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logging.info("스케줄러 종료됨")
        print("[스케줄러 종료됨]")
