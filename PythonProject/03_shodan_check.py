#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import re
import json
import time
import argparse
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ======================
# OpenCTI 설정
# ======================
OPENCTI_API_URL = "http://172.30.163.202:8080/graphql"
OPENCTI_API_KEY = "1a54db41-fa8a-4b0a-bbae-67793140ea75"

HEADERS = {
    "Authorization": f"Bearer {OPENCTI_API_KEY}",
    "Content-Type": "application/json",
}

# ======================
# Shodan 기본 키 (override 가능)
# ======================
SHODAN_API_KEY_DEFAULT = "KpBzwCfzMG6VfFiXsmFIGJyMkedlT1Mw"

# ======================
# 경로 설정
# ======================
ARTIFACT_DIR = "./artifacts"  # HTML 등 분석 산출물 저장 폴더
os.makedirs(ARTIFACT_DIR, exist_ok=True)

# ======================
# 공통 유틸
# ======================
def extract_ip(text: str) -> Optional[str]:
    if not text:
        return None
    m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return m.group() if m else None

def is_int_str(s: str) -> bool:
    try:
        int(s)
        return True
    except Exception:
        return False

def safe_get(d: dict, path: List[str], default=None):
    cur = d
    try:
        for k in path:
            if isinstance(cur, dict):
                cur = cur.get(k)
            else:
                return default
        return cur if cur is not None else default
    except Exception:
        return default

def truncate(s: Any, n: int = 400):
    s = "" if s is None else str(s)
    return (s[:n] + "…") if len(s) > n else s

# ======================
# OpenCTI GraphQL (스키마 자동 감지)
# ======================
def _normalize_labels(objlabel_raw) -> List[Dict[str, str]]:
    """
    objectLabel 응답을 어떤 스키마든 통일: List[{"id":..., "value":...}]
    - 리스트 스키마: [{"id":"...","value":"..."}, ...]
    - edges 스키마: {"edges":[{"node":{"id":"...","value":"..."}}]}
    - 단일 객체: {"id":"...","value":"..."}
    """
    labels: List[Dict[str, str]] = []
    if not objlabel_raw:
        return labels

    if isinstance(objlabel_raw, list):
        # 리스트 스키마
        for item in objlabel_raw:
            if isinstance(item, dict) and item.get("value"):
                labels.append({"id": item.get("id"), "value": item.get("value")})
        return labels

    if isinstance(objlabel_raw, dict):
        # edges 스키마 혹은 단일 객체
        edges = objlabel_raw.get("edges")
        if isinstance(edges, list):
            for ed in edges:
                node = (ed or {}).get("node") or {}
                if node.get("value"):
                    labels.append({"id": node.get("id"), "value": node.get("value")})
            return labels
        # 단일 객체
        if objlabel_raw.get("value"):
            labels.append({"id": objlabel_raw.get("id"), "value": objlabel_raw.get("value")})
            return labels

    return labels

def get_recent_reports(limit: int = 5) -> List[Dict[str, Any]]:
    """
    objectLabel 스키마 자동 감지:
      A안: 리스트 스키마
      B안: edges/node 스키마
    """
    query_a = f"""
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
    query_b = f"""
    query Reports {{
      reports(first: {limit}, orderBy: created_at, orderMode: desc) {{
        edges {{
          node {{
            id
            name
            objectLabel {{
              edges {{
                node {{ id value }}
              }}
            }}
          }}
        }}
      }}
    }}
    """

    # 먼저 A안 시도
    resp = requests.post(OPENCTI_API_URL, json={"query": query_a}, headers=HEADERS, timeout=30)
    data = resp.json()
    if resp.status_code == 200 and "errors" not in data:
        nodes = []
        for e in data.get("data", {}).get("reports", {}).get("edges", []):
            n = e.get("node") or {}
            n["objectLabel"] = _normalize_labels(n.get("objectLabel"))
            nodes.append(n)
        return nodes

    # A안 실패 시 B안 폴백
    resp_b = requests.post(OPENCTI_API_URL, json={"query": query_b}, headers=HEADERS, timeout=30)
    data_b = resp_b.json()
    if resp_b.status_code != 200 or "errors" in data_b:
        raise RuntimeError(f"GraphQL Error: {data_b.get('errors') or data.get('errors')}")

    nodes = []
    for e in data_b.get("data", {}).get("reports", {}).get("edges", []):
        n = e.get("node") or {}
        n["objectLabel"] = _normalize_labels(n.get("objectLabel"))
        nodes.append(n)
    return nodes

def labels_to_ports(labels: Optional[List[Dict[str, Any]]]) -> List[int]:
    ports: List[int] = []
    for l in (labels or []):
        v = (l.get("value") or "").strip().lower()
        if not v:
            continue
        # 포트 라벨 규칙 예시: "22", "ssh", "ssh:2222"
        if v == "ssh":
            ports.append(22)
        elif v.startswith("ssh:"):
            _, p = v.split(":", 1)
            if is_int_str(p):
                ports.append(int(p))
        elif is_int_str(v):
            ports.append(int(v))
    return sorted(set(ports))

def add_note_to_report(report_id: str, title: str, content_md: str) -> Optional[str]:
    """
    OpenCTI에 Note 추가 (Report에 귀속)
    """
    mutation = """
    mutation NoteAdd($input: NoteAddInput!) {
      noteAdd(input: $input) {
        id
        content
      }
    }
    """
    variables = {
        "input": {
            "attribute_abstract": title,
            "content": content_md,
            "objects": [report_id]
        }
    }
    resp = requests.post(OPENCTI_API_URL, json={"query": mutation, "variables": variables}, headers=HEADERS, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        print(f"[ERROR] OpenCTI Note 추가 실패: {data['errors']}")
        return None
    nid = data["data"]["noteAdd"]["id"]
    print(f"[OK] OpenCTI Note 추가: {nid}")
    return nid

# ======================
# Shodan
# ======================
def query_shodan_host(ip: str, api_key: str, timeout: int = 10) -> Dict[str, Any]:
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {"key": api_key}
    resp = requests.get(url, params=params, timeout=timeout)
    resp.raise_for_status()
    return resp.json()

def infer_protocol_from_entry(entry: Dict[str, Any]) -> str:
    data_text = (entry.get("data") or "")
    try:
        data_l = data_text.lower()
    except Exception:
        data_l = str(data_text).lower()
    product = (entry.get("product") or "").lower()
    transport = (entry.get("transport") or "").lower()

    if entry.get("http") or "http" in product or "http" in data_l:
        return "http/https(web)"
    if "ssh" in product or "ssh" in data_l:
        return "ssh"
    if "ftp" in product or "ftp" in data_l:
        return "ftp"
    if "smtp" in product or "esmtp" in data_l:
        return "smtp"
    if entry.get("ssl") or "tls" in data_l or "ssl" in data_l:
        return "ssl/tls(https/imap/ftps 등)"
    if product:
        return product
    if transport:
        return transport
    return "unknown"

def find_entries_for_port(host_json: Dict[str, Any], port: int) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for entry in host_json.get("data", []):
        try:
            if int(entry.get("port", -1)) == int(port):
                hits.append(entry)
        except Exception:
            continue
    return hits

# ======================
# HTML 내 하드코딩 의심 정보 추출
# ======================
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws(.{0,20})?(secret|key)['\"=:]\s*([A-Za-z0-9/+=]{30,})"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "Generic Bearer/JWT": re.compile(r"(?:eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,})"),
    "Email": re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    "IP Address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "Password-like": re.compile(r"(?i)(password|passwd|pwd)['\"=:]\s*([^\s\"']{6,})"),
    "Token-like": re.compile(r"(?i)(api[_\-]?key|token|secret)['\"=:]\s*([^\s\"']{10,})"),
}

def extract_hardcoded_from_html(html: str) -> Dict[str, List[str]]:
    findings: Dict[str, List[str]] = {}
    text = html if isinstance(html, str) else str(html)
    for k, rgx in SECRET_PATTERNS.items():
        matches = list({m if isinstance(m, str) else (m[0] if isinstance(m, tuple) else str(m)) for m in rgx.findall(text)})
        if matches:
            findings[k] = matches[:50]
    return findings

def save_html_artifact(ip: str, port: int, html: str) -> str:
    fname = os.path.join(ARTIFACT_DIR, f"{ip}_{port}_html.txt")
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html if isinstance(html, str) else str(html))
    return fname

def save_findings_artifact(ip: str, port: int, findings: Dict[str, List[str]]) -> str:
    fname = os.path.join(ARTIFACT_DIR, f"{ip}_{port}_findings.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    return fname

# ======================
# 워커: (IP,Port) 단위 처리
# ======================
def worker(ip: str, port: int, report_id: str, report_name: str, shodan_key: str,
           retries: int = 2, backoff: float = 1.5) -> Dict[str, Any]:
    attempt = 0
    while True:
        try:
            host_json = query_shodan_host(ip, shodan_key)
            entries = find_entries_for_port(host_json, port)
            if not entries:
                return {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "report_id": report_id,
                    "report_name": report_name,
                    "ip": ip,
                    "port": port,
                    "found": False,
                    "message": f"포트 {port} 엔트리 없음",
                    "host_summary": {
                        "ip_str": host_json.get("ip_str"),
                        "org": host_json.get("org"),
                        "os": host_json.get("os"),
                        "ports": host_json.get("ports", [])
                    }
                }

            matches = []
            for e in entries:
                artifacts: Dict[str, str] = {}
                http_obj = e.get("http") or {}
                html = http_obj.get("html")
                if html:
                    html_path = save_html_artifact(ip, port, html)
                    findings = extract_hardcoded_from_html(html)
                    if findings:
                        findings_path = save_findings_artifact(ip, port, findings)
                        artifacts["html_path"] = html_path
                        artifacts["findings_path"] = findings_path
                    else:
                        artifacts["html_path"] = html_path

                matches.append({
                    "port": e.get("port"),
                    "transport": e.get("transport"),
                    "inferred_protocol": infer_protocol_from_entry(e),
                    "product": e.get("product"),
                    "version": e.get("version"),
                    "banner_sample": truncate(e.get("data"), 1000),
                    "http": {
                        "host": safe_get(e, ["http", "host"]),
                        "title": safe_get(e, ["http", "title"]),
                        "server": safe_get(e, ["http", "server"]),
                        "x_powered_by": safe_get(e, ["http", "x_powered_by"]),
                        "favicon": safe_get(e, ["http", "favicon", "hash"]),
                        "robots": safe_get(e, ["http", "robots"])
                    },
                    "ssl": e.get("ssl"),
                    "artifacts": artifacts
                })

            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "report_id": report_id,
                "report_name": report_name,
                "ip": ip,
                "port": port,
                "found": True,
                "ip_str": host_json.get("ip_str"),
                "org": host_json.get("org"),
                "os": host_json.get("os"),
                "matches": matches
            }

        except requests.HTTPError as he:
            status = he.response.status_code if he.response is not None else None
            text = he.response.text[:500] if he.response is not None and he.response.text else ""
            attempt += 1
            if attempt > retries or status in (401, 402):
                return {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "report_id": report_id,
                    "report_name": report_name,
                    "ip": ip,
                    "port": port,
                    "found": False,
                    "error": "http_error",
                    "status_code": status,
                    "detail": text
                }
            time.sleep(backoff * attempt)
        except requests.RequestException as re:
            attempt += 1
            if attempt > retries:
                return {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "report_id": report_id,
                    "report_name": report_name,
                    "ip": ip,
                    "port": port,
                    "found": False,
                    "error": "request_exception",
                    "detail": str(re)[:500]
                }
            time.sleep(backoff * attempt)
        except Exception as e:
            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "report_id": report_id,
                "report_name": report_name,
                "ip": ip,
                "port": port,
                "found": False,
                "error": "unhandled_exception",
                "detail": str(e)[:500]
            }

# ======================
# Note 콘텐츠 생성 (Markdown)
# ======================
def build_note_markdown(rec: Dict[str, Any]) -> str:
    ts = rec.get("timestamp")
    ip = rec.get("ip")
    port = rec.get("port")
    org = rec.get("org") or "-"
    osname = rec.get("os") or "-"
    found = rec.get("found")

    header = f"### Shodan 확인 결과 — {ip}:{port}\n- 시각: {ts}\n- 조직/OS: {org} / {osname}\n"

    if not found:
        reason = rec.get("message") or rec.get("error") or "해당 포트 결과 없음"
        return header + f"- 상태: **미발견**\n- 비고: {reason}\n"

    rows = []
    artifacts_lines = []
    for m in rec.get("matches", []):
        proto = m.get("inferred_protocol") or "-"
        product = m.get("product") or "-"
        version = m.get("version") or "-"
        title = safe_get(m, ["http", "title"]) or "-"
        server = safe_get(m, ["http", "server"]) or "-"
        xpb = safe_get(m, ["http", "x_powered_by"]) or "-"
        banner = truncate(m.get("banner_sample"), 200)
        rows.append(f"| {proto} | {product} | {version} | {truncate(title,60)} | {truncate(server,60)} | {truncate(xpb,60)} | {banner} |")

        art = m.get("artifacts") or {}
        if art.get("html_path"):
            artifacts_lines.append(f"- HTML 저장: `{art['html_path']}`")
        if art.get("findings_path"):
            try:
                with open(art["findings_path"], "r", encoding="utf-8") as f:
                    findings = json.load(f)
                if findings:
                    klist = ", ".join(list(findings.keys())[:6])
                    artifacts_lines.append(f"  - 하드코딩 의심 추출(JSON): `{art['findings_path']}` (항목: {klist})")
            except Exception:
                artifacts_lines.append(f"  - 하드코딩 의심 추출(JSON): `{art['findings_path']}`")

    table = (
        "\n**요약 표**\n\n"
        "| 프로토콜 | 제품 | 버전 | HTTP Title | HTTP Server | X-Powered-By | 배너(일부) |\n"
        "|---|---|---|---|---|---|---|\n" + "\n".join(rows) + "\n"
        if rows else "\n- (표시할 매치 없음)\n"
    )

    artifacts_md = "\n".join(artifacts_lines) if artifacts_lines else "- (추가 산출물 없음)"
    footer = (
        "\n**산출물(Artifacts)**\n"
        f"{artifacts_md}\n"
        "\n> 주: HTML에서 발견된 키/토큰/비번 등은 운영환경과 무관할 수 있으므로 별도 검증이 필요합니다."
    )

    return header + table + footer

# ======================
# 메인
# ======================
def main(shodan_key: str, out_file: str, limit: int, workers: int, push: bool):
    print("[INFO] OpenCTI에서 Report 데이터를 가져옵니다...")
    reports = get_recent_reports(limit=limit)
    print(f"[INFO] 총 {len(reports)}개의 Report 확인됨")

    tasks: List[Tuple[str, int, str, str]] = []
    for r in reports:
        rid = r.get("id", "")
        rname = r.get("name", "")
        ip = extract_ip(rname)
        if not ip:
            print(f"[WARN] Report 제목에서 IP 추출 실패: {rname}")
            continue
        ports = labels_to_ports(r.get("objectLabel"))
        if not ports:
            print(f"[WARN] 포트 라벨 없음: {rname} ({ip})")
            continue
        for p in ports:
            tasks.append((ip, p, rid, rname))

    if not tasks:
        print("[INFO] 처리할 (IP,Port) 작업이 없습니다.")
        return

    print(f"[INFO] 총 {len(tasks)}개의 (IP, Port) 작업 생성됨")

    cnt = 0
    with ThreadPoolExecutor(max_workers=workers) as ex, open(out_file, "a", encoding="utf-8") as fh:
        futures = {ex.submit(worker, ip, port, rid, rname, shodan_key): (ip, port, rid, rname) for (ip, port, rid, rname) in tasks}
        for fut in as_completed(futures):
            rec = fut.result()
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            cnt += 1
            if cnt % 10 == 0:
                fh.flush()

            ip, port, rid, rname = futures[fut]
            print(f"[DONE] {ip}:{port} -> raw 기록됨")

            if push:
                title = f"Shodan 결과 요약 – {ip}:{port}"
                content = build_note_markdown(rec)
                add_note_to_report(rid, title, content)

    print(f"[INFO] 완료. 총 {cnt}건 기록 → {out_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OpenCTI 보고서(IP,Port) → Shodan 조회 → Note 등록 및 HTML 의심정보 추출 (스키마 자동 감지)"
    )
    parser.add_argument("--limit", type=int, default=500, help="OpenCTI에서 가져올 Report 개수")
    parser.add_argument("--out", default="results.jsonl", help="출력 파일 경로(JSON Lines)")
    parser.add_argument("--workers", type=int, default=6, help="동시 작업 수")
    parser.add_argument("--shodan-key", default=SHODAN_API_KEY_DEFAULT, help="Shodan API Key (기본값: 코드 하드코딩)")
    parser.add_argument("--no-push", action="store_true", help="OpenCTI Note 등록 비활성화")
    args = parser.parse_args()

    if not args.shodan_key:
        raise SystemExit("ERROR: Shodan API Key가 필요합니다. --shodan-key 또는 코드 내 기본값을 확인하세요.")

    main(
        shodan_key=args.shodan_key,
        out_file=args.out,
        limit=args.limit,
        workers=args.workers,
        push=(not args.no_push),
    )
