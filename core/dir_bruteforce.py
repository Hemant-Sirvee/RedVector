import requests
from concurrent.futures import ThreadPoolExecutor

WORDLIST = "wordlists/common.txt"

def check_directory(base_url, path):
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        if response.status_code in [200, 301, 302, 403]:
            return f"[FOUND] {url} (Status: {response.status_code})"
    except requests.RequestException:
        pass
    return None

def run_dir_bruteforce(target_url, threads=20, wordlist=WORDLIST):
    print(f"\n[📂] Starting Directory Bruteforce on {target_url}\n")

    results = []
    try:
        with open(wordlist, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist}")
        return []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_directory, target_url, path) for path in paths]
        for future in futures:
            result = future.result()
            if result:
                print(result)
                results.append(result)

    if not results:
        print("[!] No directories found.")
    else:
        print(f"\n[✓] Found {len(results)} directories.\n")

    return results
