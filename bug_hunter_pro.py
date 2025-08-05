import asyncio
import requests
import json
import socket
import nmap
import os
from bs4 import BeautifulSoup
from datetime import datetime

# Create logs directory if not exists
if not os.path.exists("logs"):
    os.makedirs("logs")

# - Subdomain Enumeration (Basic Placeholder) -
def enumerate_subdomains(domain):
    # Placeholder: No real enumeration without API keys or wordlists
    # Returns common subdomains for demonstration
    subdomains = [f"www.{domain}", f"api.{domain}"]
    found_subdomains = []
    for sub in subdomains:
        try:
            socket.gethostbyname(sub)
            found_subdomains.append(sub)
        except socket.gaierror:
            continue
    return found_subdomains


# - Port Scanning -
def scan_ports(domain):
    nm = nmap.PortScanner()
    open_ports = []
    try:
        # Resolve IP
        ip = socket.gethostbyname(domain)
        print(f"[INFO] Resolved {domain} -> {ip}")

        # Primary scan
        print(f"[INFO] Starting primary scan on {ip}...")
        nm.scan(hosts=ip, arguments="-T4 --top-ports 1000")


        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port, info in nm[ip][proto].items():
                    if info['state'] == 'open':
                        open_ports.append(port)

        # Fallback scan if no open ports found
        if not open_ports:
            print("[WARNING] No open ports found. Retrying with -Pn...")
            nm.scan(hosts=ip, arguments="-Pn -T4 --top-ports 1000")

            if ip in nm.all_hosts():
                for proto in nm[ip].all_protocols():
                    for port, info in nm[ip][proto].items():
                        if info['state'] == 'open':
                            open_ports.append(port)

        return open_ports

    except socket.gaierror:
        print(f"[ERROR] Could not resolve domain: {domain}")
        return []
    except Exception as e:
        print(f"[ERROR] Port scan failed: {str(e)}")
        return []


# - Vulnerability Testing -
def test_xss(url):
    payload = "<script>alert('XSS')</script>"
    try:
        res = requests.get(url, params={"q": payload}, timeout=5)
        return payload in res.text
    except:
        return False

def test_sqli(url):
    payload = "' OR '1'='1"
    try:
        res = requests.get(url, params={"id": payload}, timeout=5)
        return "error" in res.text.lower() or "syntax" in res.text.lower()
    except:
        return False

def test_lfi(url):
    payloads = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"]
    for payload in payloads:
        try:
            res = requests.get(url, params={"file": payload}, timeout=5)
            if "root:" in res.text:
                return True
        except:
            continue
    return False


# - Reporting -
def save_reports(domain, subdomains, open_ports, vulnerabilities):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"logs/{domain}_{timestamp}.log"

    # Log output
    with open(log_filename, "w") as log_file:
        log_file.write(f"Scan results for {domain}\n")
        log_file.write(f"Subdomains: {subdomains}\n")
        log_file.write(f"Open ports: {open_ports}\n")
        log_file.write(f"Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}\n")

    # JSON report
    json_filename = f"logs/{domain}_{timestamp}.json"
    with open(json_filename, "w") as json_file:
        json.dump({
            "domain": domain,
            "subdomains": subdomains,
            "open_ports": open_ports,
            "vulnerabilities": vulnerabilities
        }, json_file, indent=2)

    # Markdown report
    md_filename = f"logs/{domain}_{timestamp}.md"
    with open(md_filename, "w") as md_file:
        md_file.write(f"# Bug Hunter Report: {domain}\n\n")
        md_file.write(f"**Subdomains:** {', '.join(subdomains)}\n\n")
        md_file.write(f"**Open Ports:** {open_ports}\n\n")
        md_file.write("**Vulnerabilities:**\n")
        for vuln_type, results in vulnerabilities.items():
            md_file.write(f"- {vuln_type}: {results}\n")

    # HTML report
    html_filename = f"logs/{domain}_{timestamp}.html"
    with open(html_filename, "w") as html_file:
        html_file.write(f"<html><head><title>Bug Hunter Report for {domain}</title></head><body>")
        html_file.write(f"<h1>Scan results for {domain}</h1>")
        html_file.write(f"<p><strong>Subdomains:</strong> {', '.join(subdomains)}</p>")
        html_file.write(f"<p><strong>Open Ports:</strong> {open_ports}</p>")
        html_file.write("<h2>Vulnerabilities:</h2><ul>")
        for vuln_type, results in vulnerabilities.items():
            html_file.write(f"<li>{vuln_type}: {results}</li>")
        html_file.write("</ul></body></html>")

    print(f"[+] Log saved to {log_filename}")
    print(f"[+] Reports generated for {domain} in JSON, Markdown, and HTML.")


# - Main Async Flow -
async def main():
    domain = input("Enter target (domain or URL): ").strip()
    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    print("[1] Enumerating subdomains...")
    subdomains = enumerate_subdomains(domain)
    print(f"Found {len(subdomains)} subdomains: {subdomains}\n")

    print("[2] Scanning ports...")
    open_ports = scan_ports(domain)
    print(f"Open ports: {open_ports}\n")

    print("[3] Checking for vulnerabilities...")
    vulnerabilities = {"XSS": [], "SQLi": [], "LFI": []}

    for sub in subdomains or [domain]:
        url = f"http://{sub}"
        if test_xss(url):
            vulnerabilities["XSS"].append(sub)
        if test_sqli(url):
            vulnerabilities["SQLi"].append(sub)
        if test_lfi(url):
            vulnerabilities["LFI"].append(sub)

    # Display summary
    print(f"Scan results for {domain}")
    print(f"Subdomains: {subdomains}")
    print(f"Open ports: {open_ports}")
    print(f"Vulnerabilities: {json.dumps(vulnerabilities, indent=2)}\n")
    print("=== SUMMARY OF CRITICAL FINDINGS ===")
    if not any(vulnerabilities.values()):
        print("No critical vulnerabilities found.")

    save_reports(domain, subdomains, open_ports, vulnerabilities)


if __name__ == "__main__":
    asyncio.run(main())
