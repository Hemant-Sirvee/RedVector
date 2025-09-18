# core/port_scan.py
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 6379: "Redis", 27017: "MongoDB"
}

def grab_banner(ip, port):
    """Grab service banner / version info"""
    try:
        if port == 80:  # HTTP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                http_req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode()
                sock.sendall(http_req)
                response = sock.recv(1024).decode(errors="ignore")
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()
                return None

        elif port == 443:  # HTTPS
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    http_req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode()
                    ssock.sendall(http_req)
                    response = ssock.recv(1024).decode(errors="ignore")
                    for line in response.splitlines():
                        if line.lower().startswith("server:"):
                            return line.strip()
                    return "HTTPS (encrypted, no banner)"
        else:
            # Default: try plain banner grab
            with socket.socket() as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode(errors="ignore").strip()
                if banner:
                    return banner

    except Exception:
        return None
    return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = COMMON_PORTS.get(port, "Unknown")

                # Try banner grabbing
                banner = grab_banner(ip, port)
                if banner:
                    service_info = f"{service} ({banner})"
                else:
                    service_info = service

                return (port, service_info)
    except:
        pass
    return None

def run_port_scan(target, threads=100):
    print(f"\n[🚪] Running Port Scan on {target}...\n")

    # Handle URL or hostname
    from urllib.parse import urlparse
    if "://" in target:
        parsed = urlparse(target)
        target = parsed.hostname

    try:
        ip = socket.gethostbyname(target)
        print(f"[+] Resolved IP: {ip}")
    except Exception as e:
        print("[!] Failed to resolve domain:", e)
        return []

    ports_to_scan = sorted(set(list(COMMON_PORTS.keys()) + list(range(1, 1025))))
    results = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports_to_scan]
        for future in futures:
            result = future.result()
            if result and result not in results:
                port, service_info = result
                print(f"[OPEN] Port {port} - {service_info}")
                results.append(result)

    print(f"\n[✓] Found {len(results)} open ports.\n")
    return results
