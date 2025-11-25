#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import time
import socket
import requests

# ======================
# OpenCTI 설정
# ======================
OPENCTI_API_URL = "http://127.0.0.1:8080/graphql"  # OpenCTI GraphQL API URL
OPENCTI_API_KEY = "1a54db41-fa8a-4b0a-bbae-67793140ea75"  # API KEY 입력

HEADERS = {
    "Authorization": f"Bearer {OPENCTI_API_KEY}",
    "Content-Type": "application/json",
}

# ======================
# 공통 유틸
# ======================
def extract_ip(text: str):
    """문자열에서 IPv4 주소 추출"""
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
# OpenCTI Report 조회
# ======================
def get_recent_reports(limit=500):
    """OpenCTI에서 최신 Report 목록을 가져옴"""
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

# ======================
# OpenCTI 노트 추가
# ======================
def add_note_to_report(report_id: str, content: str):
    """Report에 Note 추가"""
    mutation = """
    mutation NoteAdd($input: NoteAddInput!) {
      noteAdd(input: $input) { id }
    }
    """
    variables = {
        "input": {
            "attribute_abstract": "SSH Banner Scan Result",
            "content": content,
            "objects": [report_id],
        }
    }
    resp = requests.post(OPENCTI_API_URL, json={"query": mutation, "variables": variables},
                         headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        print(f"[ERROR] Note 추가 실패: {data['errors']}")
    else:
        print(f"[INFO] Note 추가 완료: {data['data']['noteAdd']['id']}")

# ======================
# SSH 배너 수집
# ======================
def grab_ssh_banner(ip: str, port: int, timeout=8):
    """SSH 포트에 접속 후 배너 확인"""
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
# 라벨 → SSH 포트 추출
# ======================
def labels_to_ssh_ports(labels):
    """
    Report 라벨에서 SSH 포트 추출
    - 'ssh' → 22
    - 'ssh:2222' → 2222
    - '2222' → 그대로 숫자로
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
# 메인
# ======================
if __name__ == "__main__":
    print("[INFO] OpenCTI에서 Report 데이터를 가져옵니다...")
    reports = get_recent_reports(limit=500)  # 최신 50개 Report 가져오기
    print(f"[INFO] 총 {len(reports)}개의 Report 확인됨")

    for report in reports:
        report_id = report["id"]
        report_name = report["name"]
        ip = extract_ip(report_name)

        if not ip:
            print(f"[WARN] Report 제목에서 IP 추출 실패: {report_name}")
            continue

        labels = report.get("objectLabel") or []
        ssh_ports = labels_to_ssh_ports(labels)

        if not ssh_ports:
            print(f"[INFO] {ip} → SSH 라벨 없음, 스킵")
            continue

        print(f"[INFO] {ip} → SSH 포트 대상: {ssh_ports}")

        banner_results = []
        for port in ssh_ports:
            ok, line = grab_ssh_banner(ip, port)
            banner_results.append(line)
            print(line)

        # 수집 결과를 Note로 기록
        if banner_results:
            note_content = f"### SSH Banner Scan Result for {ip}\n" + "\n".join(banner_results)
            add_note_to_report(report_id, note_content)

    print("[INFO] 모든 Report 처리 완료")
