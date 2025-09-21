import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import os
import html

# ---------- Load Payloads from Local Files ----------
def load_payloads(file_path):
    """Load payloads from a local text file."""
    if not os.path.exists(file_path):
        print(f"[!] Payload file not found: {file_path}")
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        payloads = [line.strip() for line in f if line.strip()]
    print(f"[+] Loaded {len(payloads)} payloads from {file_path}")
    return payloads

XSS_PAYLOADS = load_payloads("wordlists/xss.txt")
SQLI_PAYLOADS = load_payloads("wordlists/sqli.txt")

# ---------- Vulnerability Scan ----------
def run_vuln_scan(target):
    print(f"\n[+] Running Vulnerability Scan on: {target}")
    discovered_params = set()

    try:
        response = requests.get(target, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")

        # Extract links with parameters
        for link in soup.find_all("a", href=True):
            url = urljoin(target, link["href"])
            if "?" in url:
                discovered_params.add(url)

        # Extract forms
        for form in soup.find_all("form"):
            action = form.get("action")
            form_url = urljoin(target, action)
            inputs = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
            if inputs:
                params = "&".join([f"{i}=test" for i in inputs])
                separator = "&" if "?" in form_url else "?"
                discovered_params.add(f"{form_url}{separator}{params}")

    except Exception as e:
        print(f"[!] Failed to crawl {target}: {e}")

    if not discovered_params:
        print("[!] No parameterized endpoints found.")
        return

    print(f"[*] Found {len(discovered_params)} parameterized endpoints.")
    for url in discovered_params:
        print(f"\n[*] Testing endpoint: {url}")
        check_redirection(url)
        test_for_xss(url)
        test_for_sqli(url)

# ---------- Redirection Check ----------
def check_redirection(url):
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        if len(r.history) > 0:
            for resp in r.history:
                print(f"[Redirect] {url} redirected via {resp.status_code} to {r.url}")
    except requests.RequestException:
        print(f"[!] Failed to check redirection for: {url}")

# ---------- XSS Test with false positive handling ----------
def test_for_xss(url):
    for payload in XSS_PAYLOADS:
        test_url = inject_payload(url, payload)
        try:
            r = requests.get(test_url, timeout=10, allow_redirects=True)
            unescaped_text = html.unescape(r.text)

            if payload in unescaped_text:
                print(f"[XSS-WARNING] Payload reflected: {test_url} (manual verification recommended)")
            

            if len(r.history) > 0:
                print(f"[Redirect during XSS test] {test_url} redirected to {r.url}")
        except requests.RequestException:
            print(f"[!] Failed XSS test for: {test_url}")

# ---------- SQLi Test with response comparison ----------
def test_for_sqli(url):
    sql_errors = ["you have an error in your sql syntax",
                  "warning: mysql",
                  "unclosed quotation mark",
                  "sqlstate"]

    try:
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        normal_query = "&".join([f"{k}=test123" for k in query.keys()])
        normal_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{normal_query}"
        baseline_resp = requests.get(normal_url, timeout=10, allow_redirects=True).text
    except requests.RequestException:
        print(f"[!] Cannot get baseline response for {url}")
        return

    for payload in SQLI_PAYLOADS:
        test_url = inject_payload(url, payload)
        try:
            r = requests.get(test_url, timeout=10, allow_redirects=True)
            diff_length = abs(len(r.text) - len(baseline_resp))
            error_detected = any(err.lower() in r.text.lower() for err in sql_errors)

            if error_detected or diff_length > 20:  # lower threshold for sensitivity
                print(f"[SQLi-WARNING] Possible SQL Injection at: {test_url} (manual verification recommended)")
            

            if len(r.history) > 0:
                print(f"[Redirect during SQLi test] {test_url} redirected to {r.url}")
        except requests.RequestException:
            print(f"[!] Failed SQLi test for: {test_url}")

# ---------- Inject Payload ----------
def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    new_query = "&".join([f"{k}={payload}" for k in query.keys()])
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
