from flask import Flask, request, render_template
import re
from datetime import datetime
import time
import os

app = Flask(__name__)

# RATE LIMIT SETTINGS

request_tracker = {}

REQUEST_LIMIT = 10
TIME_WINDOW = 20



# SQL INJECTION PATTERNS


sql_patterns = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"(\bOR\b|\bAND\b).*=.*",
    r"UNION.*SELECT",
    r"DROP\s+TABLE",
]


# XSS PATTERNS

xss_patterns = [
    r"<script.*?>.*?</script.*?>",
    r"javascript:",
    r"onerror=",
    r"onload=",
    r"alert\s*\(",
]



# LFI / DIRECTORY TRAVERSAL

lfi_patterns = [
    r"\.\./",
    r"/etc/passwd",
    r"boot.ini",
    r"windows/system32",
]



# COMMAND INJECTION

command_patterns = [
    r";",
    r"\|\|",
    r"&&",
    r"cmd.exe",
    r"powershell",
    r"bash",
    r"whoami",
]



# SQL INJECTION DETECTION

def detect_sql_injection(data):

    for pattern in sql_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False


# XSS DETECTION

def detect_xss(data):

    for pattern in xss_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False


# LFI DETECTION

def detect_lfi(data):

    for pattern in lfi_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False


# COMMAND INJECTION DETECTION

def detect_command_injection(data):

    for pattern in command_patterns:
        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False


# ATTACK LOGGING

def log_attack(ip, attack_type, url):

    timestamp = datetime.now()

    log_entry = (
        f"{timestamp} | "
        f"IP: {ip} | "
        f"Attack: {attack_type} | "
        f"URL: {url}\n"
    )

    with open("attacks.log", "a") as file:
        file.write(log_entry)


# RATE LIMIT CHECK

def check_rate_limit(ip):

    current_time = time.time()

    if ip not in request_tracker:
        request_tracker[ip] = []

    # Keep only recent requests
    request_tracker[ip] = [
        timestamp
        for timestamp in request_tracker[ip]
        if current_time - timestamp < TIME_WINDOW
    ]

    # Add current request
    request_tracker[ip].append(current_time)

    # Check request limit
    if len(request_tracker[ip]) > REQUEST_LIMIT:
        return True

    return False


# MAIN ROUTE

@app.route('/')
def home():

    ip = request.remote_addr
    url = request.url

    print("\n===== Incoming Request =====")
    print("IP:", ip)
    print("URL:", url)

    # RATE LIMIT DETECTION
    if check_rate_limit(ip):

        print("⚠ Rate Limit Exceeded!")

        log_attack(ip, "Rate Limit Exceeded", url)

        return "Blocked: Too Many Requests", 429


    # SQL INJECTION DETECTION
    if detect_sql_injection(url):

        print("⚠ SQL Injection Detected!")

        log_attack(ip, "SQL Injection", url)

        return "Blocked: SQL Injection Detected", 403


    # XSS DETECTION
    if detect_xss(url):

        print("⚠ XSS Attack Detected!")

        log_attack(ip, "XSS Attack", url)

        return "Blocked: XSS Attack Detected", 403


    # LFI DETECTION
    if detect_lfi(url):

        print("⚠ LFI / Directory Traversal Detected!")

        log_attack(ip, "LFI / Directory Traversal", url)

        return "Blocked: LFI Attack Detected", 403


    # COMMAND INJECTION DETECTION
    if detect_command_injection(url):

        print("⚠ Command Injection Detected!")

        log_attack(ip, "Command Injection", url)

        return "Blocked: Command Injection Detected", 403


    return "Request Allowed"


# DASHBOARD ROUTE

@app.route('/dashboard')
def dashboard():

    if os.path.exists("attacks.log"):

        with open("attacks.log", "r") as file:
            logs = file.readlines()

    else:
        logs = []

    attack_count = len(logs)

    # Attack counts
    sql_count = 0
    xss_count = 0
    lfi_count = 0
    command_count = 0
    rate_limit_count = 0

    for log in logs:

        if "SQL Injection" in log:
            sql_count += 1

        if "XSS Attack" in log:
            xss_count += 1

        if "LFI / Directory Traversal" in log:
            lfi_count += 1

        if "Command Injection" in log:
            command_count += 1

        if "Rate Limit Exceeded" in log:
            rate_limit_count += 1

    logs = "".join(logs[-20:])

    return render_template(
        "dashboard.html",
        attack_count=attack_count,
        sql_count=sql_count,
        xss_count=xss_count,
        lfi_count=lfi_count,
        command_count=command_count,
        rate_limit_count=rate_limit_count,
        logs=logs
    )


if __name__ == '__main__':
    app.run(debug=True)