#!/usr/bin/env python3
import asyncio
import nmap
import requests
import socket
import re
import os
import json
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------
# Utility: Clean and normalize target
# ---------------------------
def normalize_target(target):
    parsed = urlparse(target)
    if not parsed.scheme:
        target = "http://" + target
        parsed = urlparse(target)
    return parsed.hostname

# ---------------------------
# Logging
# ---------------------------
def log_result(domain, content):
    os.makedirs("logs", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"logs/{domain}_{timestamp}.log"
    with open(log_file, "w") as log:
        log.write(content)
    print(f"[+] Log saved to {log_file}")

# ---------------------------
# Subdomain Enumeration (Threaded)
# ---------------------------
def check_subdomain(sub, domain):
    subdomain = f"{sub}.{domain}"
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except socket.gaierror:
        return None

def enumerate_subdomains(domain):
    print("[1] Enumerating subdomains...")
    common_subs = ["www", "api", "dev", "test", "staging"]
    found_subs = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_subdomain, sub, domain) for sub in common_subs]
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_subs.append(result)

    print(f"Found {len(found_subs)} subdomains: {found_subs}")
    return found_subs

# ---------------------------
# Port Scanning with Nmap
# ---------------------------
def scan_ports(target):
    print("\n[2] Scanning ports...")
    nm = nmap.PortScanner()
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Could not resolve target to IP. Skipping port scan.")
        return []

    # Corrected Nmap command
    nm.scan(hosts=ip, arguments="-Pn -T4 --top-ports 1000")
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, port_data in nm[host][proto].items():
                if port_data['state'] == "open":
                    open_ports.append(port)

    print(f"Open ports: {open_ports}")
    return open_ports

# ---------------------------
# Basic Vulnerability Testing (Threaded)
# ---------------------------
def test_sqli(url):
    payloads = ["' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\""]
    for payload in payloads:
        try:
            res = requests.get(url + "?id=" + payload, timeout=5)
            if re.search(r"sql|mysql|syntax|error", res.text, re.I):
                return f"SQLi possible with payload: {payload}"
        except requests.RequestException:
            continue
    return None

def test_lfi(url):
    payloads = ["../../../../etc/passwd", "../../../../windows/win.ini"]
    for payload in payloads:
        try:
            res = requests.get(url + "?file=" + payload, timeout=5)
            if "root:x:" in res.text or "[extensions]" in res.text:
                return f"LFI possible with payload: {payload}"
        except requests.RequestException:
            continue
    return None

def run_vulnerability_tests(url):
    print("\n[3] Checking for vulnerabilities...")
    vulnerabilities = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(test_sqli, url), executor.submit(test_lfi, url)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                vulnerabilities.append(result)

    return vulnerabilities

# ---------------------------
# Reporting
# ---------------------------
def generate_reports(domain, subdomains, ports, vulnerabilities):
    os.makedirs("reports", exist_ok=True)
    report_data = {
        "domain": domain,
        "subdomains": subdomains,
        "open_ports": ports,
        "vulnerabilities": vulnerabilities
    }

    # JSON
    with open(f"reports/{domain}_report.json", "w") as f:
        json.dump(report_data, f, indent=4)

    # Markdown
    with open(f"reports/{domain}_report.md", "w") as f:
        f.write(f"# Bug Hunter Report for {domain}\n\n")
        f.write(f"**Subdomains:** {subdomains}\n\n")
        f.write(f"**Open Ports:** {ports}\n\n")
        f.write("**Vulnerabilities:**\n")
        for v in vulnerabilities:
            f.write(f"- {v}\n")

    # HTML
    with open(f"reports/{domain}_report.html", "w") as f:
        f.write("<html><head><title>Bug Hunter Report</title></head><body>")
        f.write(f"<h1>Report for {domain}</h1>")
        f.write(f"<h2>Subdomains</h2><p>{subdomains}</p>")
        f.write(f"<h2>Open Ports</h2><p>{ports}</p>")
        f.write("<h2>Vulnerabilities</h2><ul>")
        for v in vulnerabilities:
            f.write(f"<li>{v}</li>")
        f.write("</ul></body></html>")

    print(f"[+] Reports generated for {domain} in JSON, Markdown, and HTML.")

# ---------------------------
# Main Async Flow
# ---------------------------
async def main():
    target = input("Enter target (domain or URL): ").strip()
    domain = normalize_target(target)

    subdomains = enumerate_subdomains(domain)
    open_ports = scan_ports(domain)
    vulnerabilities = run_vulnerability_tests(target)

    # Combine results for logging
    log_content = (
        f"Target: {target}\n"
        f"Subdomains: {subdomains}\n"
        f"Open Ports: {open_ports}\n"
        f"Vulnerabilities: {vulnerabilities}\n"
    )
    log_result(domain, log_content)

    generate_reports(domain, subdomains, open_ports, vulnerabilities)

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    asyncio.run(main())
