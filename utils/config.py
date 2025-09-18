# core/config.py

# Default scan timeout
DEFAULT_TIMEOUT = 10

# Number of CVEs to fetch
CVE_LIMIT = 3

# Custom User-Agent (for web scan and requests)
USER_AGENT = "RedVector/1.0"

# DNS Resolver settings
DNS_SERVERS = ["8.8.8.8", "1.1.1.1"]

# Directory for storing reports
REPORT_DIR = "results"

# Wordlists (if needed later)
WORDLISTS = {
    "subdomains": "data/subdomains.txt",
    "admin_panels": "data/admin_panels.txt"
}
