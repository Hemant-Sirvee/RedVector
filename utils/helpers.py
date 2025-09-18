# utils/helpers.py
from urllib.parse import urlparse
import re

def is_valid_ip(ip):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip) is not None

def is_valid_url(url):
    return url.startswith("http://") or url.startswith("https://")

def safe_filename(name):
    return re.sub(r'[^\w\-_.]', '_', name)

def print_banner_line():
    print("=" * 60)

def normalize_target(target):
    """
    Accepts host, IP, or URL and returns (host, port, scheme).
    - Default port 80 for http, 443 for https, None otherwise.
    """
    if "://" not in target:
        # Not a full URL, assume it's a hostname or IP
        return target, None, None  

    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme

    # Default ports if missing
    if scheme == "http" and not port:
        port = 80
    elif scheme == "https" and not port:
        port = 443

    return host, port, scheme
