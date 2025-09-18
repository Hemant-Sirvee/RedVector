import requests

def lookup_cves(service_name):
    print(f"\n[🧠] Searching CVEs for service: {service_name}...\n")

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": service_name,
        "resultsPerPage": 3
    }

    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        cves = data.get("vulnerabilities", [])
        if not cves:
            print("  [!] No CVEs found for this service.")
            return []

        results = []
        for item in cves:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            description = cve_data.get("descriptions", [{}])[0].get("value", "No description")
            metrics = cve_data.get("metrics", {})
            score = "N/A"

            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            result = f"{cve_id} (Score: {score})\n{description[:200]}...\nhttps://nvd.nist.gov/vuln/detail/{cve_id}"
            print("  -", result)
            results.append(result)

        return results

    except Exception as e:
        print(f"  [!] CVE lookup failed: {e}")
        return []
