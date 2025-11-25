#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import socket
import requests
from contextlib import closing

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ======================
# OpenCTI 설정
# ======================
OPENCTI_API_URL = "http://127.0.0.1:8080/graphql"
OPENCTI_API_KEY = "1a54db41-fa8a-4b0a-bbae-67793140ea75"

HEADERS = {
    "Authorization": f"Bearer {OPENCTI_API_KEY}",
    "Content-Type": "application/json",
}

# ======================
# 공통 설정
# ======================
SCREENSHOT_DIR = "./01_web_check"
HTTP_TIMEOUT = 12
TCP_TIMEOUT = 8

# ======================
# 유틸
# ======================
def extract_ip(text: str):
    if not text:
        return None
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return m.group() if m else None

def is_int_str(s: str):
    try:
        int(s)
        return True
    except Exception:
        return False

# ======================
# OpenCTI 조회 (스키마: objectLabel는 리스트)
# ======================
def get_recent_reports(limit=700):
    query = f"""
    query Reports {{
      reports(first: {limit}, orderBy: created_at, orderMode: desc) {{
        edges {{
          node {{
            id
            name
            objectLabel {{ id value }}
          }}
        }}
      }}
    }}
    """
    resp = requests.post(OPENCTI_API_URL, json={"query": query}, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL Error: {data['errors']}")
    return [e["node"] for e in data.get("data", {}).get("reports", {}).get("edges", [])]

def get_recent_events(limit=700):
    query = f"""
    query Events {{
      events(first: {limit}, orderBy: created_at, orderMode: desc) {{
        edges {{
          node {{
            id
            name
            objectLabel {{ id value }}
          }}
        }}
      }}
    }}
    """
    resp = requests.post(OPENCTI_API_URL, json={"query": query}, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"GraphQL Error: {data['errors']}")
    return [e["node"] for e in data.get("data", {}).get("events", {}).get("edges", [])]

# ======================
# OpenCTI 노트
# ======================
def add_note_to_report(report_id: str, content: str):
    mutation = """
    mutation NoteAdd($input: NoteAddInput!) {
      noteAdd(input: $input) { id }
    }
    """
    variables = {"input": {
        "attribute_abstract": "Web Port Screenshot Result",
        "content": content,
        "objects": [report_id],
    }}
    resp = requests.post(OPENCTI_API_URL, json={"query": mutation, "variables": variables},
                         headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        print(f"[ERROR] Report Note 추가 실패: {data['errors']}")
    else:
        print(f"[INFO] Report Note 추가 완료: {data['data']['noteAdd']['id']}")

def add_note_to_event(event_id: str, content: str):
    mutation = """
    mutation NoteAdd($input: NoteAddInput!) {
      noteAdd(input: $input) { id }
    }
    """
    variables = {"input": {
        "attribute_abstract": "SSH Port Check History",
        "content": content,
        "objects": [event_id],
    }}
    resp = requests.post(OPENCTI_API_URL, json={"query": mutation, "variables": variables},
                         headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        print(f"[ERROR] Event Note 추가 실패: {data['errors']}")
    else:
        print(f"[INFO] Event Note 추가 완료: {data['data']['noteAdd']['id']}")

# ======================
# 라벨 파싱
# ======================
def labels_to_web_tasks(labels):
    """
    Report 라벨 → 웹 스크린샷 태스크
    - '80' → http/https 둘 다 시도
    - 'http:8080' or 'https:8443' → 해당 스킴만
    """
    tasks = []
    for l in (labels or []):
        v = (l.get("value") or "").strip().lower()
        if not v:
            continue
        if v.startswith("http:") or v.startswith("https:"):
            scheme, p = v.split(":", 1)
            if is_int_str(p):
                tasks.append(("web", scheme, int(p)))
        elif is_int_str(v):
            p = int(v)
            tasks.append(("web", "http", p))
            tasks.append(("web", "https", p))
        # 그 외 포맷은 무시
    seen, uniq = set(), []
    for t in tasks:
        k = (t[0], t[1], t[2])
        if k not in seen:
            seen.add(k)
            uniq.append(t)
    return uniq

def labels_to_ssh_ports(labels):
    """
    Event 라벨 → SSH 포트 리스트
    - 'ssh' → 22
    - 'ssh:2222' → 2222
    - '2222' → 2222 (숫자면 그대로)
    """
    ports = []
    for l in (labels or []):
        v = (l.get("value") or "").strip().lower()
        if not v:
            continue
        if v == "ssh":
            ports.append(22)
        elif v.startswith("ssh:"):
            _, p = v.split(":", 1)
            if is_int_str(p):
                ports.append(int(p))
        elif is_int_str(v):
            ports.append(int(v))
    return sorted(set(ports))

# ======================
# 웹 스크린샷
# ======================
def make_chrome_driver():
    opts = Options()
    opts.add_argument("--headless=new")                    # Headless
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--window-size=1366,768")
    # 인증서/혼합컨텐츠 오류를 무시하고 진행
    opts.add_argument("--ignore-certificate-errors")
    opts.add_argument("--allow-insecure-localhost")
    opts.add_argument("--allow-running-insecure-content")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=opts)
    driver.set_page_load_timeout(HTTP_TIMEOUT)
    return driver

def capture_http_screenshot(driver, ip: str, port: int, scheme: str, save_dir=SCREENSHOT_DIR):
    os.makedirs(save_dir, exist_ok=True)
    url = f"{scheme}://{ip}:{port}"
    try:
        driver.get(url)
        fn = os.path.join(save_dir, f"{ip}_{port}_{scheme}.png")
        driver.save_screenshot(fn)
        print(f"[OK] {url} → {fn}")
        return fn, True, ""
    except Exception as e:
        print(f"[FAIL] {url}: {e}")
        return None, False, str(e)

# ======================
# SSH 배너
# ======================
def grab_ssh_banner(ip: str, port: int, timeout=TCP_TIMEOUT):
    start = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode(errors="ignore").strip()
            if not banner:
                try:
                    sock.sendall(b"\n")
                    banner = sock.recv(256).decode(errors="ignore").strip()
                except Exception:
                    pass
            end = time.strftime("%Y-%m-%d %H:%M:%S")
            return True, f"[{start} → {end}] {ip}:{port} SSH banner: {banner or '(no banner)'}"
    except Exception as e:
        end = time.strftime("%Y-%m-%d %H:%M:%S")
        return False, f"[{start} → {end}] {ip}:{port} SSH connect failed: {e}"

# ======================
# 메인
# ======================
if __name__ == "__main__":
    # ---------- 1) 최신 Report 순회 → 웹 스크린샷 ----------
    reports = get_recent_reports(limit=500)
    print(f"[INFO] 가져온 Report 수: {len(reports)}")

    with closing(make_chrome_driver()) as driver:
        for r in reports:
            report_id = r["id"]
            report_name = r["name"]
            ip = extract_ip(report_name)

            if not ip:
                print(f"[WARN] Report 제목에서 IP 추출 실패: {report_name}")
                continue

            labels = r.get("objectLabel") or []
            web_tasks = labels_to_web_tasks(labels)
            if not web_tasks:
                print(f"[INFO] {ip} 웹 라벨 없음, 스킵")
                continue

            print(f"[INFO] {ip} → 웹 태스크: {web_tasks}")

            web_results = []
            for _, scheme, port in web_tasks:
                fn, ok, err = capture_http_screenshot(driver, ip, port, scheme)
                if ok:
                    web_results.append(f"- {scheme}://{ip}:{port} → {os.path.basename(fn)}")
                else:
                    web_results.append(f"- {scheme}://{ip}:{port} → FAILED ({err})")

            if web_results:
                note = f"### Web Port Screenshot Result for {ip}\n" + "\n".join(web_results)
                add_note_to_report(report_id, note)

    # ---------- 2) 최신 Event 순회 → SSH 배너 ----------
    events = get_recent_events(limit=500)
    print(f"[INFO] 가져온 Event 수: {len(events)}")

    for ev in events:
        event_id = ev["id"]
        event_name = ev["name"]

        ip2 = extract_ip(event_name)
        if not ip2:
            print(f"[WARN] Event 제목에서 IP 추출 실패: {event_name}")
            continue

        elabels = ev.get("objectLabel") or []
        ssh_ports = labels_to_ssh_ports(elabels)

        if not ssh_ports:
            print(f"[INFO] {event_name} SSH 라벨 없음, 스킵")
            continue

        print(f"[INFO] {ip2} → SSH 대상 포트(이벤트 라벨): {ssh_ports}")

        history = ["### SSH Port Check History"]
        for p in ssh_ports:
            ok, line = grab_ssh_banner(ip2, p)
            history.append(f"- {line}")

        if len(history) > 1:
            add_note_to_event(event_id, "\n".join(history))

    print("[INFO] 처리 완료")
