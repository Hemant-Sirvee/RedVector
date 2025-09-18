import requests
from bs4 import BeautifulSoup

XSS_PAYLOAD = "<script>alert(1337)</script>"
SQLI_PAYLOAD = "' OR '1'='1"
REDIRECT_PAYLOAD = "https://evil.com"

def find_forms(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.find_all("form")
    except:
        return []

def test_xss(url):
    print("\n[💉] Testing for XSS...")
    forms = find_forms(url)
    for form in forms:
        action = form.get("action")
        method = form.get("method", "get").lower()
        inputs = form.find_all("input")
        data = {}
        for inp in inputs:
            name = inp.get("name")
            if name:
                data[name] = XSS_PAYLOAD

        target = url if not action else (url.rstrip("/") + "/" + action.lstrip("/"))
        try:
            if method == "post":
                r = requests.post(target, data=data)
            else:
                r = requests.get(target, params=data)

            if XSS_PAYLOAD in r.text:
                print(f"  [!] Possible XSS found at: {target}")
        except:
            pass

def test_sqli(url):
    print("\n[🧨] Testing for SQL Injection...")
    test_url = url + "?id=" + SQLI_PAYLOAD
    try:
        r = requests.get(test_url)
        if "sql" in r.text.lower() or "syntax" in r.text.lower():
            print(f"  [!] Possible SQL Injection at: {test_url}")
    except:
        pass

def test_redirect(url):
    print("\n[🔁] Testing for Open Redirect...")
    if "?" not in url:
        print("  [~] No query parameter to test redirect.")
        return

    test_url = url.split("?")[0] + "?next=" + REDIRECT_PAYLOAD
    try:
        r = requests.get(test_url, allow_redirects=False)
        if REDIRECT_PAYLOAD in r.headers.get("Location", ""):
            print(f"  [!] Possible Open Redirect at: {test_url}")
    except:
        pass

def run_vuln_scan(url):
    test_xss(url)
    test_sqli(url)
    test_redirect(url)
