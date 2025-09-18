import socket
import whois
import dns.resolver
import requests
import json
import time


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

    for record_type in ["A", "MX", "NS"]:
        try:
            answers = resolver.resolve(target, record_type)
            print(f"  {record_type} Records:")
            for r in answers:
                print("   ", r.to_text())
        except dns.resolver.NoAnswer:
            print(f"  [!] No {record_type} record found.")
        except dns.resolver.NXDOMAIN:
            print(f"  [!] Domain {target} does not exist.")
            break
        except dns.exception.Timeout:
            print(f"  [!] DNS query for {record_type} timed out.")
        except Exception as e:
            print(f"  [!] DNS lookup error for {record_type}: {e}")

    # --- Subdomain Enumeration ---
    enumerate_subdomains(target)


def enumerate_subdomains(domain):
    print("\n[🌐] Enumerating subdomains using crt.sh...")

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; RedVector/1.0)"}

    retries = 3  # retry crt.sh up to 3 times
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=90)
            if response.status_code != 200:
                print(f"[!] crt.sh request failed (status {response.status_code})")
                return

            try:
                data = response.json()
            except json.JSONDecodeError:
                text = response.text.strip()
                if text.endswith(",]"):
                    text = text.replace(",]", "]")
                data = json.loads(text)

            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    for sub in name_value.split("\n"):
                        sub = sub.strip().lower()
                        if sub and "*" not in sub:
                            subdomains.add(sub)

            if not subdomains:
                print("[!] No subdomains found.")
                return

            print(f"[✓] Found {len(subdomains)} potential subdomains.")
            print("[*] Checking which ones are publicly accessible...\n")

            alive = []
            for sub in sorted(subdomains):
                url = f"http://{sub}"
                try:
                    r = requests.get(url, timeout=7, allow_redirects=True)
                    if r.status_code in [200, 401, 403]:
                        print(f"[ALIVE] {sub} ({r.status_code})")
                        alive.append(f"{sub} ({r.status_code})")
                except requests.RequestException:
                    pass  # Ignore unreachable ones

            if not alive:
                print("[!] No accessible subdomains found.")
            else:
                print(f"\n[✓] {len(alive)} subdomains are publicly accessible/misconfigured.")
            return  # success → exit loop

        except Exception as e:
            print(f"[!] crt.sh attempt {attempt+1} failed: {e}")
            if attempt < retries - 1:
                print("[*] Retrying in 5s...")
                time.sleep(5)
            else:
                print("[✗] All retries failed. crt.sh seems down.")
