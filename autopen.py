#!/usr/bin/env python3
# autopen_extended.py (최신 패치됨)

import argparse
import subprocess
import os
import sys
import shutil
import datetime
import json
import requests
from pathlib import Path

# --- 유틸 함수들 ---
def run_cmd(cmd, capture=True, timeout=None):
    try:
        if capture:
            p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
            return p.returncode, p.stdout + ("\n[stderr]\n" + p.stderr if p.stderr else "")
        else:
            p = subprocess.run(cmd, shell=True, timeout=timeout)
            return p.returncode, ""
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"

def sanitize_filename(s):
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in s)

def ensure_tools():
    tools = ["nmap", "whatweb", "searchsploit", "subfinder", "nikto", "nuclei"]
    return [t for t in tools if shutil.which(t) is None]

# --- 스캔 함수들 ---
def nmap_scan(target, outdir):
    fname = sanitize_filename(target)
    out_file = outdir / f"nmap_{fname}.txt"
    cmd = f"nmap -p- -sV -sC -Pn -T4 -oN {out_file} {target}"
    rc, _ = run_cmd(cmd, capture=True, timeout=60*30)
    return rc, out_file.read_text() if out_file.exists() else ""

def whatweb_scan(target, outdir):
    fname = sanitize_filename(target)
    out_file = outdir / f"whatweb_{fname}.txt"
    cmd = f"whatweb --log-verbose={out_file} {target}"
    rc, _ = run_cmd(cmd, capture=True, timeout=300)
    return rc, out_file.read_text() if out_file.exists() else ""

def subdomain_scan(target, outdir):
    fname = sanitize_filename(target)
    out_file = outdir / f"subfinder_{fname}.txt"
    cmd = f"subfinder -d {target} -silent -o {out_file}"
    rc, _ = run_cmd(cmd, capture=True, timeout=120)
    return rc, out_file.read_text() if out_file.exists() else ""

def nikto_scan(target, outdir):
    fname = sanitize_filename(target)
    out_file = outdir / f"nikto_{fname}.txt"
    cmd = f"nikto -host {target} -output {out_file}"
    rc, _ = run_cmd(cmd, capture=True, timeout=600)
    return rc, out_file.read_text() if out_file.exists() else ""

def nuclei_scan(target, outdir):
    fname = sanitize_filename(target)
    out_file = outdir / f"nuclei_{fname}.txt"
    cmd = f"nuclei -u http://{target} -o {out_file}"
    rc, _ = run_cmd(cmd, capture=True, timeout=600)
    return rc, out_file.read_text() if out_file.exists() else ""

def searchsploit_lookup(service_name):
    cmd = f"searchsploit \"{service_name}\" -w"
    rc, out = run_cmd(cmd, capture=True, timeout=30)
    return out if rc == 0 else ""

def metasploit_commands(service):
    return f"search {service}"

def query_nvd_api(keyword):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def parse_nmap_for_services(text):
    services = []
    for line in text.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 4:
                services.append(" ".join(parts[3:]))
    return services

def enrich_services_with_cve_and_exploit(services):
    enriched = {}
    for svc in services:
        key = svc.strip()
        enriched[key] = {
            "cve": query_nvd_api(key),
            "exploitdb": searchsploit_lookup(key),
            "metasploit": metasploit_commands(key)
        }
    return enriched

# --- 리포트 생성 ---
def create_report(target, outdir, results):
    fname = sanitize_filename(target)
    rpt = outdir / f"{fname}_report.html"
    with rpt.open("w", encoding="utf-8") as f:
        f.write(f"<html><head><title>Report for {target}</title></head><body>")
        f.write(f"<h1>Report for {target}</h1><p><em>{datetime.datetime.utcnow().isoformat()} UTC</em></p>")

        for name, content in results.items():
            if isinstance(content, str):
                f.write(f"<h2>{name}</h2><pre>{content}</pre>")

        enrichment = results.get("enrichment", {})
        f.write("<h2>Service-based Enrichment</h2>")
        for svc, data in enrichment.items():
            f.write(f"<h3>{svc}</h3><ul>")
            if isinstance(data["cve"], dict) and "vulnerabilities" in data["cve"]:
                for c in data["cve"]["vulnerabilities"]:
                    info = c.get("cve", {})
                    desc = info.get("descriptions", [{}])[0].get("value", "")
                    cvss = c.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "?")
                    color = "green" if isinstance(cvss, (int, float)) and cvss < 4 else "orange" if isinstance(cvss, (int, float)) and cvss < 7 else "red"
                    f.write(f"<li><b style='color:{color}'>CVSS {cvss}</b>: {info.get('id')} - {desc}</li>")
            else:
                f.write("<li>No CVE data</li>")
            f.write("<li><b>ExploitDB:</b><pre>" + data.get("exploitdb", "No results") + "</pre></li>")
            f.write("<li><b>Metasploit Commands:</b><pre>" + data.get("metasploit", "None") + "</pre></li>")
            f.write("</ul>")

        f.write("</body></html>")
    return rpt

# --- 메인 실행 ---
def main():
    parser = argparse.ArgumentParser(description="Auto recon with CVE/ExploitDB/Metasploit mapping + OSINT")
    parser.add_argument("--targets", required=True, help="File with list of targets")
    parser.add_argument("--outdir", required=True, help="Output directory")
    args = parser.parse_args()

    targets_file = Path(args.targets)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    rawdir = outdir / "raw"
    rawdir.mkdir(exist_ok=True)

    missing = ensure_tools()
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}", file=sys.stderr)
        return

    targets = [line.strip() for line in targets_file.read_text().splitlines() if line.strip()]

    for target in targets:
        print(f"[+] Processing: {target}")
        fname = sanitize_filename(target)
        results = {}

        _, results["WhatWeb"] = whatweb_scan(target, rawdir)
        _, results["Nmap"] = nmap_scan(target, rawdir)
        _, results["Subfinder"] = subdomain_scan(target, rawdir)
        _, results["Nikto"] = nikto_scan(target, rawdir)
        _, results["Nuclei"] = nuclei_scan(target, rawdir)

        services = parse_nmap_for_services(results["Nmap"])
        results["enrichment"] = enrich_services_with_cve_and_exploit(services)

        rpt_path = create_report(target, outdir, results)
        print(f"[+] Report generated: {rpt_path}")

    print("[+] All tasks complete.")

if __name__ == "__main__":
    main()

