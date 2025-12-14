import os
import subprocess
import sys
import base64
from urllib.parse import urlparse
from datetime import datetime
import argparse
import asyncio
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response, Request
from fastapi.responses import HTMLResponse
from contextlib import asynccontextmanager
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates


# --- Configuration ---
TOOL_NAME = "R.A.P.T.O.R."
VERSION = "8.3"  # Incremented version
NMAP_PATH = "nmap"
DIRB_PATH = "dirb"
NIKTO_PATH = "nikto"
SQLMAP_PATH = "sqlmap"
DIRB_WORDLIST = "/usr/share/wordlists/dirb/common.txt"

# --- Global State ---
report_data = {}
current_log_callback = None 

# --- Core Functions ---

def add_to_report(tool, content):
    if tool not in report_data:
        report_data[tool] = ""
    report_data[tool] += content + "\n"

def generate_html_report(target, scan_date_str):
    report_sections = []
    for tool, data in report_data.items():
        report_sections.append(f"<h2>{tool.upper()} Results</h2>")
        report_sections.append("<pre>")
        report_sections.append(data)
        report_sections.append("</pre>")
    
    report_content_html = "\n".join(report_sections)
    
    parsed_url = urlparse(target)
    target_display = parsed_url.hostname if parsed_url.hostname else target

    # Read CSS content from the external file for the static report
    css_content = ""
    try:
        with open("static/RCE.css", "r") as f:
            css_content = f.read()
    except FileNotFoundError:
        print("[ERROR] static/RCE.css not found. Report might not be styled correctly.")

    full_html_report = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>R.A.P.T.O.R. Scan Report - {target_display}</title>
    <style>
        {css_content}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>R.A.P.T.O.R. Scan Report</h1>
            <p class="subtitle">Target: {target_display}</p>
            <p class="scan-date">Scan Date: {scan_date_str}</p>
        </header>
        
        <main>
            {report_content_html}
        </main>
    </div>
</body>
</html>
"""
    return full_html_report

async def run_command_async(command, tool_name):
    current_log_callback(f"Starting {tool_name} scan...", "SYSTEM")
    add_to_report(tool_name, f"--- Running command: {' '.join(command)} ---\n")
    
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )

        while True:
            line = await process.stdout.readline()
            if not line:
                break
            decoded_line = line.decode().strip()
            current_log_callback(decoded_line, tool_name)
            add_to_report(tool_name, decoded_line)
        
        await process.wait()
        return_code = process.returncode

        if return_code == 0:
            current_log_callback(f"{tool_name} scan completed successfully.", "SYSTEM")
        else:
            current_log_callback(f"{tool_name} scan finished with exit code {return_code}.", "ERROR")
    except FileNotFoundError:
        current_log_callback(f"Command '{command[0]}' not found. Make sure {tool_name} is installed and in your PATH.", "ERROR")
    except Exception as e:
        current_log_callback(f"An error occurred while running {tool_name}: {e}", "ERROR")

async def run_scans_async(target, scans):
    global report_data
    report_data = {} # Reset report data for each new scan
    
    parsed_url = urlparse(target)
    hostname = parsed_url.hostname if parsed_url.hostname else target.split('/')[0]

    current_log_callback(f"--- Starting Scan on {target} ---", "SYSTEM")

    if scans.get('nmap'):
        await run_command_async([NMAP_PATH, "-sV", "-T4", "-A", hostname], "Nmap")
    
    if scans.get('dirb'):
        if os.path.exists(DIRB_WORDLIST):
            await run_command_async([DIRB_PATH, target, DIRB_WORDLIST], "Dirb")
        else:
            current_log_callback(f"Dirb wordlist not found at {DIRB_WORDLIST}. Skipping scan.", "ERROR")

    if scans.get('nikto'):
        await run_command_async([NIKTO_PATH, "-h", target], "Nikto")

    if scans.get('sqlmap'):
        current_log_callback("SQLMap can be dangerous. Using safe, non-interactive options.", "SYSTEM")
        await run_command_async([SQLMAP_PATH, "-u", target, "--batch", "--level=3", "--risk=2", "--dbs"], "SQLMap")

    current_log_callback("--- All Scans Completed ---", "SYSTEM")
    
    scan_date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return generate_html_report(target, scan_date_str)

import socketio # Added socketio import

# --- Web Mode (FastAPI) ---

sio = socketio.AsyncServer(cors_allowed_origins="*", async_mode='asgi') # Initialize Socket.IO AsyncServer with async_mode

templates = Jinja2Templates(directory="templates")

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"R.A.P.T.O.R. v{VERSION} Web Mode starting...")
    yield
    print(f"R.A.P.T.O.R. v{VERSION} Web Mode shutting down.")

app = FastAPI(lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Mount the Socket.IO ASGI app
socketio_asgi_app = socketio.ASGIApp(sio, app)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("RCE.html", {"request": request})

@sio.event
async def connect(sid, environ):
    print(f"Client connected: {sid}")
    global current_log_callback

    def web_log(message, tool_name):
        try:
            asyncio.create_task(sio.emit("log", {"tool": tool_name, "msg": message}, room=sid))
        except RuntimeError:
            pass

    current_log_callback = web_log
    current_log_callback(f"R.A.P.T.O.R. v{VERSION} Console Initialized.", "SYSTEM")

@sio.event
async def disconnect(sid):
    print(f"Client disconnected: {sid}")

@sio.on("start_attack")
async def start_attack_handler(sid, data):
    target = data.get("target")
    scans = data.get("scans", {})
    
    if not target:
        current_log_callback("No target specified.", "ERROR")
        return

    asyncio.create_task(run_scans_async_wrapper(target, scans, sid))

@sio.on("stop_attack")
async def stop_attack_handler(sid):
    current_log_callback("Stop command received (not yet implemented).", "SYSTEM")

async def run_scans_async_wrapper(target, scans, sid):
    """Wrapper to run async scans and handle report emission."""
    final_html_report = await run_scans_async(target, scans)
    await sio.emit("attack_complete", {"report": final_html_report}, room=sid)


def run_web_mode():
    print(f"Starting {TOOL_NAME} v{VERSION} in Web Mode...")
    print(f"Access the web UI at: http://127.0.0.1:8000")
    # Run the combined Socket.IO and FastAPI app
    uvicorn.run(socketio_asgi_app, host="0.0.0.0", port=8000)

# --- Terminal Mode ---

def terminal_log(message, tool_name):
    print(f"[{tool_name}] {message}")

async def run_terminal_mode_async(args):
    global current_log_callback
    current_log_callback = terminal_log

    scans = {
        'nmap': args.nmap or args.all,
        'dirb': args.dirb or args.all,
        'nikto': args.nikto or args.all,
        'sqlmap': args.sqlmap or args.all,
    }

    if not any(scans.values()):
        scans = {s: True for s in scans}
        print("[SYSTEM] No specific scans selected, defaulting to all scans.")

    print(f"--- {TOOL_NAME} v{VERSION} ---")
    print(f"Target: {args.target}")
    print(f"Scans to run: {[s for s, run in scans.items() if run]}")
    
    print("\nStarting scans...")
    final_html_report = await run_scans_async(args.target, scans)
    
    safe_target_name = urlparse(args.target).hostname.replace('.', '_').replace(':', '_').replace('/', '_') if urlparse(args.target).hostname else "report"
    report_filename = f"raptor_report_{{safe_target_name}}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    with open(report_filename, "w") as f:
        f.write(final_html_report)
    
    print(f"\n[SYSTEM] Scan complete! Report saved to {report_filename}")
    print(f"[SYSTEM] Open '{report_filename}' in your web browser to view the detailed report.")

# --- Main Entry Point ---

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} - Rapid Automated Penetration Testing and Offensive Reconnaissance."
    )
    parser.add_argument("target", nargs='?', help="Target URL (e.g., http://example.com) for terminal mode.")
    parser.add_argument("--nmap", action="store_true", help="Run Nmap scan in terminal mode.")
    parser.add_argument("--dirb", action="store_true", help="Run Dirb scan in terminal mode.")
    parser.add_argument("--nikto", action="store_true", help="Run Nikto scan in terminal mode.")
    parser.add_argument("--sqlmap", action="store_true", help="Run SQLMap scan in terminal mode.")
    parser.add_argument("--all", action="store_true", help="Run all available scans in terminal mode.")
    parser.add_argument("--web", action="store_true", help="Start in web mode.")

    args = parser.parse_args()

    if args.web:
        run_web_mode()
    elif args.target: # If a target is provided, assume terminal mode
        asyncio.run(run_terminal_mode_async(args))
    else: # No web flag and no target, prompt for mode
        # Check if running in an interactive terminal
        if sys.stdin.isatty():
            while True:
                print("\nChoose a mode:")
                print("  1: Web Mode (Interactive UI in browser)")
                print("  2: Terminal Mode (Command-line interaction, HTML report)")
                print("  q: Quit")
                choice = input("Enter your choice: ").strip()
                if choice == '1':
                    run_web_mode()
                    break
                elif choice == '2':
                    print("\nTo run in Terminal Mode, please execute the script with arguments:")
                    print(f"  python3 {sys.argv[0]} <target_url> [--nmap] [--dirb] [--nikto] [--sqlmap] [--all]")
                    break
                elif choice.lower() == 'q':
                    break
                else:
                    print("Invalid choice. Please try again.")
        else:
            print("Error: No mode specified and not running in an interactive terminal.")
            print("Please run with --web or a target URL and scan flags.")
            parser.print_help()
            sys.exit(1)