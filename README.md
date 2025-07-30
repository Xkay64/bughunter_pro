Bug Hunter Pro

**Bug Hunter Pro** is a Python-based **bug hunting and vulnerability scanning tool** designed for ethical hackers and cybersecurity enthusiasts.  

It performs:
 ✅ Subdomain enumeration
 ✅ Port & service scanning (via Nmap)
 ✅ Basic vulnerability testing (SQLi & LFI)
 ✅ Threaded scans for speed
 ✅ Report generation in **JSON, Markdown, and HTML**
 ✅ Automatic logging of results



**Features**

**Subdomain Enumeration:** Finds possible subdomains for the target.

**Port & Service Scanning:** Integrates with `nmap` to detect open ports.

**Vulnerability Testing:** Checks for common flaws like:
SQL Injection (SQLi)
Local File Inclusion (LFI)

**Report Generation:** Saves results in:
`logs/` directory for logs
JSON, Markdown, and HTML reports for easy sharing.



**Installation**

Clone the repository:
  bash
git clone https://github.com/xkay64/bughunter_pro.git
cd bughunter-pro

**Create a virtual environment**
python3 -m venv venv
source venv/bin/activate

**Install Dependencies**
pip install -r requirements.txt

**USAGE**

python3 bug_hunter_pro.py



**EXAMPLE RUN**

Enter target (domain or URL): http://testphp.vulnweb.com
[1] Enumerating subdomains...
Found 0 subdomains: []

[2] Scanning ports...
Open ports: [80]

[3] Checking for vulnerabilities...
[+] Log saved to logs/testphp.vulnweb.com_20250730_102634.log
[+] Reports generated for testphp.vulnweb.com in JSON, Markdown, and HTML.



**DISCLAIMER** 

This tool is for educational and ethical testing purposes only.
Do not use it on targets you don’t own or have permission to test.
I am not responsible for any misuse of this tool.**
