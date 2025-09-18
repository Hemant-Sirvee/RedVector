import requests
from bs4 import BeautifulSoup

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_security_headers(headers):
    print("\n[🛡️] Security Header Check:")
    for header in SECURITY_HEADERS:
        if header in headers:
            print(f"  [+] {header}: {headers[header]}")
        else:
            print(f"  [!] {header} missing!")

def detect_forms(url, content):
    soup = BeautifulSoup(content, "html.parser")
    forms = soup.find_all("form")
    print(f"\n[🕵️] Found {len(forms)} forms on the page.")
    for idx, form in enumerate(forms):
        action = form.get("action")
        method = form.get("method", "GET").upper()
        print(f"  ↪️ Form {idx+1}: Method={method}, Action={action}")

def run_web_scan(target):
    print(f"\n[🌐] Running Web Scan on {target}...\n")

    if not target.startswith("http"):
        target = "http://" + target

    try:
        res = requests.get(target, timeout=10)
        print(f"[+] Status: {res.status_code}")
        print(f"[+] Server: {res.headers.get('Server', 'Unknown')}")
        print(f"[+] Content-Type: {res.headers.get('Content-Type', 'Unknown')}")

        check_security_headers(res.headers)
        detect_forms(target, res.text)

    except requests.exceptions.RequestException as e:
        print(f"[!] Web scan failed: {e}")
