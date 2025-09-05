#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smuggleAuto.py — single-file SAFE scanner (only needs --mode and --host)
=======================================================================
- SAFE ONLY: sends HEAD (with GET fallback). No TE/CL mixing, no smuggling payloads.
- Auto-creates: report_SMUGGLE_YYYYMMDD_HHMMSS/report.html
- URIs: use lfi.txt if present; otherwise use an embedded list.
- Optional: you may still pass --scan-cmd/--scan but they are not required.

Usage (Kali):
  python3 smuggleAuto.py --mode auto --host example.com
  python3 smuggleAuto.py --mode safe-probe --host 127.0.0.1
"""

import argparse
import csv
import json
import re
import sys
import time
import socket
import ssl
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    import http.client as httpclient
except Exception:
    import httplib as httpclient  # pragma: no cover

# ---------------- Defaults (no flags needed) ----------------
SCHEME_DEFAULT = "https"
RPS_DEFAULT = 1.0
TIMEOUT_DEFAULT = 5.0
MAX_URIS_DEFAULT = 300
BODY_BYTES_DEFAULT = 512   # richer good-request details
URIS_FILE_DEFAULT = "lfi.txt"

# -------------- Embedded URIs (fallback if lfi.txt missing) --------------
EMBEDDED_URIS = [
    "/", "/index.html", "/robots.txt", "/sitemap.xml",
    "/.git/HEAD", "/.svn/entries", "/.env", "/config.php", "/phpinfo.php",
    "/admin", "/admin/", "/admin/login", "/login", "/user/login",
    "/api", "/api/status", "/health", "/server-status",
    "/../../../../../../../../etc/passwd",
    "/..%2f..%2f..%2f..%2f..%2fetc/passwd",
    "/..%2F..%2F..%2F..%2F..%2Fetc/passwd",
    "/..;/..;/..;/..;/etc/passwd",
    "/?file=../../../../../../../../etc/passwd",
    "/?page=../../../../../../../../etc/passwd",
    "/?path=../../../../../../../../etc/passwd",
    "/?include=../../../../../../../../etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "/..%255c..%255c..%255c..%255cwindows/win.ini",
    "/?template=../../../../../../../../windows/win.ini",
    "/?view=../../../../../../../../proc/self/environ",
    "/proc/self/environ",
]

# -------------- Scan parsing (optional hints; SAFE only) --------------
SCAN_LINE_VEC = re.compile(r'\((TECL|CLTE)\s*:\s*([0-9.]+)\s*-\s*([0-9]{3})\)')
NAME_LINE = re.compile(r'^\s*\[(?P<name>[^\]]+)\]\s*:\s*(?P<status>\w+)\s*(?P<rest>.*)$')

def parse_scan_text(text: str) -> List[Dict]:
    results = []
    for line in text.splitlines():
        m = NAME_LINE.match(line)
        if not m:
            vecs = SCAN_LINE_VEC.findall(line)
            if vecs:
                results.append({
                    "name": "unnamed",
                    "status": "UNKNOWN",
                    "vectors": [{"type": v[0], "time": float(v[1]), "code": int(v[2])} for v in vecs]
                })
            continue
        name = m.group('name').strip()
        status = m.group('status').strip()
        rest = m.group('rest') or ""
        vecs = SCAN_LINE_VEC.findall(rest)
        results.append({
            "name": name,
            "status": status,
            "vectors": [{"type": v[0], "time": float(v[1]), "code": int(v[2])} for v in vecs]
        })
    return results

def classify(entry: Dict) -> Dict:
    vectors = entry.get("vectors", [])
    info = {v["type"]: v for v in vectors}
    flags = []
    if "TECL" in info and "CLTE" in info:
        if info["TECL"]["code"] != info["CLTE"]["code"]:
            flags.append("DIFF_STATUS_CODE")
        if abs(info["TECL"]["time"] - info["CLTE"]["time"]) >= 0.5:
            flags.append("LARGE_TIME_DELTA")
    for k in ("TECL","CLTE"):
        if k in info and info[k]["code"] < 400:
            flags.append(f"{k}_NON_4XX")
    score = sum(2 if f in ("DIFF_STATUS_CODE","LARGE_TIME_DELTA") else 1 for f in flags)
    if score >= 3: label = "review-high"
    elif score == 2: label = "review-med"
    elif score == 1: label = "review-low"
    else: label = "low-interest"
    return {"label": label, "flags": sorted(set(flags)), "score": score}

# -------------- URI loading --------------
def read_uris(limit: int = MAX_URIS_DEFAULT) -> List[str]:
    p = Path(URIS_FILE_DEFAULT)
    if p.exists():
        uris = []
        for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
            s = line.strip()
            if not s or s.startswith('#'): continue
            if not s.startswith('/'):
                s = '/' + s
            uris.append(s)
            if len(uris) >= limit: break
        if uris:
            return uris
    return EMBEDDED_URIS[:limit]

# -------------- SAFE probing (HEAD with GET fallback) --------------
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

def _minimal_request(scheme: str, host: str, port: int, method: str, path: str, timeout: float, want_body_bytes:int=0) -> Tuple[int, Dict[str,str], int, Optional[bytes]]:
    start = time.time()
    if scheme == "https":
        hc = httpclient.HTTPSConnection(host, port=port, timeout=timeout, context=ssl.create_default_context())
    else:
        hc = httpclient.HTTPConnection(host, port=port, timeout=timeout)
    headers = {
        "User-Agent": "smuggleAuto-safe/2.1",
        "Accept": "*/*",
        "Connection": "close"
    }
    hc.request(method, path, headers=headers)
    resp = hc.getresponse()
    status = resp.status
    hdrs = {k: v for (k,v) in resp.getheaders()}
    body = None
    if want_body_bytes and method == "GET":
        body = resp.read(max(0, want_body_bytes))
    else:
        _ = resp.read(1)
    hc.close()
    dt = int((time.time() - start) * 1000)
    return status, hdrs, dt, body

def safe_probe(host: str, scheme: str, uris: List[str], rps: float, timeout: float, max_count: int, body_bytes:int) -> List[ProbeResult]:
    targets = uris[:max_count]
    results: List[ProbeResult] = []
    delay = 1.0 / max(0.1, rps)
    port = 443 if scheme == "https" else 80
    for path in targets:
        time.sleep(delay)
        try:
            status, headers, dt, _ = _minimal_request(scheme, host, port, "HEAD", path, timeout, want_body_bytes=0)
            results.append(ProbeResult(path, "HEAD", status, dt, headers.get("Server"), headers, None, None))
            if status in (405, 501):
                status, headers, dt, body = _minimal_request(scheme, host, port, "GET", path, timeout, want_body_bytes=body_bytes)
                snippet = None
                if body:
                    try:
                        snippet = body.decode("utf-8", errors="replace")
                    except Exception:
                        snippet = repr(body[:80])
                results.append(ProbeResult(path, "GET", status, dt, headers.get("Server"), headers, snippet, None))
        except Exception as e:
            results.append(ProbeResult(path, "HEAD", None, None, None, {}, None, str(e)))
    return results

# -------------- Plan & Report --------------
def build_plan(entries: List[Dict], uris: List[str], host: str, scheme: str) -> Dict:
    plan = {"meta": {"host": host, "scheme": scheme, "version": "2.1.0", "dry_run_only": True}, "entries": []}
    uri_cycle = uris[:30]
    if not entries:
        entries = [{"name": "no-scan", "status": "N/A", "vectors": []}]
    for i, e in enumerate(entries):
        cls = classify(e) if e.get("vectors") else {"label": "low-interest", "flags": [], "score": 0}
        start = (i * 3) % max(1, len(uri_cycle)) if uri_cycle else 0
        suggested = [uri_cycle[(start + j) % len(uri_cycle)] for j in range(3)] if uri_cycle else []
        plan["entries"].append({
            "name": e.get("name", "unnamed"),
            "status": e.get("status", "UNKNOWN"),
            "vectors": e.get("vectors", []),
            "priority": cls["label"],
            "flags": cls["flags"],
            "uri_samples": suggested,
            "request_templates": [
                {"vector": "TECL", "desc": "PLACEHOLDER ONLY", "http_text_placeholder":"### FILL-IN-MANUALLY-IN-LAB ###"},
                {"vector": "CLTE", "desc": "PLACEHOLDER ONLY", "http_text_placeholder":"### FILL-IN-MANUALLY-IN-LAB ###"}
            ]
        })
    return plan

def _esc(s: Optional[str]) -> str:
    return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _curl_example(scheme: str, host: str, path: str, method: str) -> str:
    q = quote(path, safe="/?&=:+,;@%-._~!$'()*")
    if method == "HEAD":
        return f"curl -i -k -I '{scheme}://{host}{q}' -H 'User-Agent: smuggleAuto-safe/2.1'"
    return f"curl -i -k -X {method} '{scheme}://{host}{q}' -H 'User-Agent: smuggleAuto-safe/2.1'"

def _heuristics_note(headers: Dict[str,str]) -> str:
    h = {k.lower(): v for k,v in (headers or {}).items()}
    hints = []
    if "transfer-encoding" in h:
        hints.append("Proxy adds <code>Transfer-Encoding</code>; ensure normalisation at the edge.")
    if "content-length" in h and h.get("content-length","").isdigit():
        cl = int(h["content-length"])
        if cl == 0:
            hints.append("Zero <code>Content-Length</code> on 2xx is unusual; verify upstream behaviour.")
    if "via" in h or "x-forwarded-for" in h:
        hints.append("Reverse-proxy visible; check consistency between proxy and origin responses.")
    if "cache-control" in h and "no-store" not in h["cache-control"].lower():
        hints.append("Consider <code>Cache-Control: no-store</code> for sensitive endpoints.")
    if not hints:
        hints.append("No obvious red flags from headers.")
    return "<ul>" + "".join(f"<li>{x}</li>" for x in hints) + "</ul>"

def render_html_report(host: str, scheme: str, results: List[ProbeResult], plan: Dict, out_html: Path, generated_at: str, body_bytes: int):
    good = [r for r in results if r.status is not None and 200 <= r.status <= 299]
    redir = [r for r in results if r.status is not None and 300 <= r.status <= 399]
    other = [r for r in results if (r.status is None) or (r.status >= 400)]

    def header_table():
        return f"""
        <table>
          <tr><th>Target</th><td>{_esc(scheme)}://{_esc(host)}</td></tr>
          <tr><th>Generated</th><td>{_esc(generated_at)}</td></tr>
          <tr><th>Mode</th><td>SAFE-PROBE (HEAD with GET fallback)</td></tr>
          <tr><th>URIs Probed</th><td>{len(results)}</td></tr>
          <tr><th>Counts</th><td>2xx={len(good)} &nbsp;&nbsp; 3xx={len(redir)} &nbsp;&nbsp; Other/Err={len(other)}</td></tr>
          <tr><th>Body Snippet Limit</th><td>{body_bytes} bytes for GET fallback</td></tr>
        </table>
        """

    def good_row(r: ProbeResult) -> str:
        hdrs = "".join(f"<div><code>{_esc(k)}: {_esc(v)}</code></div>" for k,v in (r.resp_headers or {}).items())
        curl = _curl_example(scheme, host, r.uri, r.method)
        req_line = f"{r.method} {r.uri} HTTP/1.1"
        req_headers = [
            ("Host", host),
            ("User-Agent", "smuggleAuto-safe/2.1"),
            ("Accept", "*/*"),
            ("Connection", "close"),
        ]
        req_hdrs_html = "".join(f"<div><code>{_esc(k)}: {_esc(v)}</code></div>" for k,v in req_headers)
        body_block = f"<pre class='body'>{_esc(r.body_snippet or '')}</pre>" if (r.method == 'GET' and r.body_snippet) else ""
        heur = _heuristics_note(r.resp_headers)

        suggestions = """
<ul>
  <li><b>Lab-only differential parsing:</b> Compare origin vs proxy responses for the same path under HEAD/GET/OPTIONS.</li>
  <li><b>Header canonicalisation:</b> Confirm hop-by-hop headers are stripped or normalised before reaching the origin.</li>
  <li><b>Strict TE/CL policy:</b> Ensure proxies reject ambiguous requests and re-encode with a single framing strategy.</li>
  <li><b>HTTP/2 termination:</b> Terminate at the edge and downgrade to a canonical HTTP/1.1 form internally.</li>
  <li><b>Logging & correlation:</b> Trace IDs across proxy/origin to spot inconsistencies in status and timing.</li>
</ul>
"""
        return f"""
<tr class="good">
  <td><code>{_esc(req_line)}</code>
    <div class="req-hdrs">{req_hdrs_html}</div>
    <div class="curl"><b>cURL:</b> <code>{_esc(curl)}</code></div>
  </td>
  <td class="center">{'' if r.status is None else r.status}</td>
  <td class="center">{'' if r.time_ms is None else r.time_ms}</td>
  <td>{hdrs}{body_block}
    <div class="notes">
      <h4>Heuristic Observations</h4>
      {heur}
      <h4>Safe Next Steps (lab-only)</h4>
      {suggestions}
    </div>
  </td>
</tr>
"""

    html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>smuggleAuto SAFE Report - {_esc(host)}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Noto Sans',sans-serif;padding:24px;max-width:1220px;margin:0 auto;background:#fafafa;color:#111}}
h1{{margin:0 0 4px 0}} small{{color:#666}}
table{{border-collapse:collapse;width:100%;margin-top:12px;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
th,td{{border:1px solid #e9e9e9;padding:10px;font-size:14px;vertical-align:top}}
th{{background:#f4f6f8;text-align:left;width:160px}}
td.center{{text-align:center}}
.section{{margin-top:26px}}
.summary table{{margin-top:0}}
.good-table th{{background:#eefaf0}}
.good-table tr.good{{background:#f8fffa}}
pre.body{{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;border:1px solid #eee;border-radius:6px;padding:8px;max-height:240px;overflow:auto}}
code{{background:#f6f8fa;padding:2px 4px;border-radius:4px}}
.req-hdrs div, .curl {{margin-top:4px}}
kbd{{background:#eee;border-radius:3px;border:1px solid #ccc;padding:2px 4px}}
.footer{{margin-top:32px;color:#666;font-size:12px}}
</style>
</head>
<body>
  <h1>smuggleAuto SAFE Report <small>{_esc(generated_at)}</small></h1>
  <div class="summary section">
    {header_table()}
  </div>

  <div class="section">
    <h2>Good Requests (2xx)</h2>
    <table class="good-table">
      <thead><tr><th>Request</th><th>Status</th><th>Time (ms)</th><th>Response</th></tr></thead>
      <tbody>
        {''.join(good_row(r) for r in good) if good else "<tr><td colspan='4'>No 2xx responses recorded.</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Redirects (3xx)</h2>
    <table>
      <thead><tr><th>Method</th><th>URI</th><th>Status</th><th>Time (ms)</th><th>Location</th></tr></thead>
      <tbody>
        {''.join(f"<tr><td>{_esc(r.method)}</td><td><code>{_esc(r.uri)}</code></td><td class='center'>{r.status}</td><td class='center'>{r.time_ms}</td><td><code>{_esc((r.resp_headers or {{}}).get('Location',''))}</code></td></tr>" for r in redir) if redir else "<tr><td colspan='5'>No 3xx responses.</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Other / Errors</h2>
    <table>
      <thead><tr><th>Method</th><th>URI</th><th>Status</th><th>Time (ms)</th><th>Server</th><th>Error</th></tr></thead>
      <tbody>
        {''.join(f"<tr><td>{_esc(r.method)}</td><td><code>{_esc(r.uri)}</code></td><td class='center'>{'' if r.status is None else r.status}</td><td class='center'>{'' if r.time_ms is None else r.time_ms}</td><td>{_esc(r.server)}</td><td>{_esc(r.error)}</td></tr>" for r in other) if other else "<tr><td colspan='6'>No 4xx/5xx/errors.</td></tr>"}
      </tbody>
    </table>
  </div>

  <div class="section">
    <h2>Plan & Hints (from Scan)</h2>
    <p>Conservative flags from external scan output (if provided). Use only in an authorized lab.</p>
    <table>
      <thead><tr><th>Name</th><th>Status</th><th>Priority</th><th>Flags</th><th>URI Samples</th></tr></thead>
      <tbody>
        {''.join(f"<tr><td><code>{_esc(e.get('name',''))}</code></td><td>{_esc(e.get('status',''))}</td><td>{_esc(e.get('priority',''))}</td><td><code>{_esc(';'.join(e.get('flags',[])))}</code></td><td><code>{_esc(' , '.join(e.get('uri_samples',[])))}</code></td></tr>" for e in plan.get('entries',[]))}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by smuggleAuto.py (SAFE). No smuggling payloads were sent.
  </div>
</body></html>
"""
    out_html.write_text(html, encoding="utf-8")

# -------------- CLI orchestration (only --mode and --host required) --------------
def main():
    ap = argparse.ArgumentParser(description="smuggleAuto.py (SAFE) — only needs --mode and --host")
    ap.add_argument("--mode", choices=["dry-run","safe-probe","auto"], required=True)
    ap.add_argument("--host", required=True)
    # Optional inputs (ignored by most users):
    ap.add_argument("--scheme", choices=["https","http"], default=SCHEME_DEFAULT)
    ap.add_argument("--scan", help="Path to a scan output file to parse (optional)")
    ap.add_argument("--scan-cmd", help="Command to execute; stdout captured as scan output (optional)")
    args = ap.parse_args()

    # Set fixed defaults (no flags needed)
    scheme = args.scheme
    rps = RPS_DEFAULT
    timeout = TIMEOUT_DEFAULT
    max_uris = MAX_URIS_DEFAULT
    body_bytes = BODY_BYTES_DEFAULT

    # Output folder
    ts = time.strftime("%Y%m%d_%H%M%S")
    outdir = Path(f"report_SMUGGLE_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)

    # Optional scan stage
    scan_text = ""
    if args.scan_cmd:
        print(f"[SCAN] Running command: {args.scan_cmd}")
        try:
            proc = subprocess.run(args.scan_cmd, shell=True, capture_output=True, text=True, timeout=300)
            scan_text = proc.stdout
            (outdir / "scan_output.txt").write_text(scan_text, encoding="utf-8")
            if proc.stderr:
                (outdir / "scan_stderr.txt").write_text(proc.stderr, encoding="utf-8")
        except Exception as e:
            (outdir / "scan_error.txt").write_text(str(e), encoding="utf-8")
            print(f"[SCAN] ERROR: {e}", file=sys.stderr)

    elif args.scan and Path(args.scan).exists():
        scan_text = Path(args.scan).read_text(encoding="utf-8", errors="ignore")
        (outdir / "scan_output.txt").write_text(scan_text, encoding="utf-8")

    entries = parse_scan_text(scan_text) if scan_text else []
    uris = read_uris()

    # Build plan + summary
    plan = build_plan(entries, uris, host=args.host, scheme=scheme)
    (outdir / "plan.json").write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    with (outdir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name","status","priority","flags","TECL(code,time)","CLTE(code,time)"])
        for e in plan["entries"]:
            v = {v["type"]: v for v in e.get("vectors", [])}
            tecl = v.get("TECL"); clte = v.get("CLTE")
            w.writerow([
                e.get("name",""), e.get("status",""), e.get("priority",""), ";".join(e.get("flags",[])),
                f"{tecl['code']},{tecl['time']}" if tecl else "",
                f"{clte['code']},{clte['time']}" if clte else ""
            ])

    # Probe if requested
    results: List[ProbeResult] = []
    if args.mode in ("safe-probe","auto"):
        print("[SAFE-PROBE] Sending HEAD/GET requests...")
        results = safe_probe(args.host, scheme, uris, rps=rps, timeout=timeout, max_count=max_uris, body_bytes=body_bytes)
        with (outdir / "probe_results.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["uri","method","status","time_ms","server","error"])
            for r in results:
                w.writerow([r.uri, r.method, r.status if r.status is not None else "", r.time_ms if r.time_ms is not None else "", r.server or "", r.error or ""])

    # Always write HTML report
    gen_at = time.strftime("%Y-%m-%d %H:%M:%S")
    out_html = outdir / "report.html"
    render_html_report(args.host, scheme, results, plan, out_html, gen_at, body_bytes=body_bytes)
    print(f"[OK] HTML report -> {out_html.resolve()}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Interrupted by user.", file=sys.stderr); sys.exit(130)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr); sys.exit(1)
