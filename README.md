# 🔍 RedVector – Web Vulnerability Assessment Toolkit

RedVector is a **CLI-based automated vulnerability assessment toolkit** written in Python. Inspired by Nikto and Nuclei, it allows security professionals and enthusiasts to perform reconnaissance, port scanning, CVE lookup, web vulnerability scanning, directory brute-forcing, and generate comprehensive reports—all in one tool.

---

## 🚀 Features

- **Reconnaissance**
  - WHOIS Lookup
  - DNS Records (A, MX, NS)
  - Subdomain Enumeration via `crt.sh`  
- **Port Scanning**
  - Fast TCP scan (common ports + 1–1024)
  - Banner grabbing for service detection
  - Automatic CVE lookup for discovered services
- **Vulnerability Scanning**
  - XSS detection
  - SQL Injection testing
  - Open Redirect testing
- **Web Security Scan**
  - Security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
  - Form detection and analysis
- **Directory Bruteforce**
  - Detect hidden directories or admin panels using wordlists
- **Reporting**
  - Generates timestamped text report in `results/` folder
  - Sections for Recon, Port Scan, Vulnerability Scan, Web Scan, and Directory Bruteforce

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/RedVector.git
cd RedVector
chmod +x setup.sh
bash ./setup.sh
```

---

## ⚡ Usage

Run the main script using:
```bash 
redvector -u <target> --scan <scan_type> [--threads <num_threads>]
```
---

## ⚙ Dependencies

**requests,**
**beautifulsoup4,** 
**dnspython,** 
**python-whois,** 
**Python ≥ 3.8**
```bash
pip install -r requirements.txt
```

## ⚠ Notes

Ensure you have permission to scan the target.

Unauthorized scanning may be illegal in many jurisdictions.

Use this tool responsibly for educational purposes or authorized penetration testing only.

Reports are generated in text format under the results/ folder.




