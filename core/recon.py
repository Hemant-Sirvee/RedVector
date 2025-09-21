import socket
import whois
import dns.resolver
import requests


def run_recon(target):
    print(f"\n[+] Running Recon Module on: {target}")

    # --- WHOIS Lookup ---
    try:
        print("\n[🔍] WHOIS Lookup:")
        w = whois.whois(target)
        print("  Registrar:", getattr(w, "registrar", "N/A"))
        print("  Creation Date:", getattr(w, "creation_date", "N/A"))
        print("  Expiration Date:", getattr(w, "expiration_date", "N/A"))
    except Exception as e:
        print("  [!] WHOIS lookup failed:", e)

    # --- DNS Records ---
    print("\n[📡] DNS Records:")
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare
    resolver.timeout = 5
    resolver.lifetime = 5

    for record_type in ["A", "MX", "NS" , "AAAA"]:
        try:
            answers = resolver.resolve(target, record_type)
            print(f"  {record_type} Records:")
            for r in answers:
                print("   ", r.to_text())
        except Exception as e:
            print(f"  [!] DNS lookup error for {record_type}: {e}")

    # --- Subdomain Enumeration ---
    enumerate_subdomains_otx(target)


def enumerate_subdomains_otx(domain):
    print("\n[🌐] Enumerating subdomains using AlienVault OTX...")

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; RedVector/1.0)"}

    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            print(f"[!] OTX request failed (status {r.status_code})")
            return []

        data = r.json()
        subdomains = set()

        for entry in data.get("url_list", []):
            url = entry.get("url", "")
            if domain in url:
                sub = url.split("/")[2]
                if sub.endswith(domain):
                    subdomains.add(sub)

        if not subdomains:
            print("[!] No subdomains found on OTX.")
            return []

        print(f"[✓] Found {len(subdomains)} potential subdomains.")
        return check_accessible_subdomains(subdomains)

    except Exception as e:
        print(f"[!] OTX lookup failed: {e}")
        return []


def check_accessible_subdomains(subdomains):
    print("[*] Checking which ones are publicly accessible...\n")

    alive = []
    for sub in sorted(subdomains):
        test_url = f"http://{sub}"
        try:
            r = requests.get(test_url, timeout=7, allow_redirects=True)
            if r.status_code in [200, 401, 403]:
                print(f"[ALIVE] {sub} ({r.status_code})")
                alive.append(f"{sub} ({r.status_code})")
        except requests.RequestException:
            pass

    if not alive:
        print("[!] No accessible subdomains found.")
    else:
        print(f"\n[✓] {len(alive)} subdomains are publicly accessible/misconfigured.")

    return alive
