#!/usr/bin/env python3


import argparse
import io
import contextlib

from core.dir_bruteforce import run_dir_bruteforce
from utils.banner import show_banner
from core.recon import run_recon
from core.port_scan import run_port_scan
from core.vuln_scan import run_vuln_scan
from core.web_scan import run_web_scan
from core.cve_lookup import lookup_cves
from utils.helpers import is_valid_ip, print_banner_line
from core.report_generator import ReportGenerator

def capture_output(func, *args, **kwargs):
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        func(*args, **kwargs)
    return buffer.getvalue().splitlines()

def main():
    show_banner()
    parser = argparse.ArgumentParser(description="RedVector - Web Vulnerability Assessment Toolkit")
    parser.add_argument("-u", "--url", required=True, help="Target domain or IP address")
    parser.add_argument("--scan", required=True, choices=["recon", "port", "vuln", "web", "dir","all"], help="Scan type")
    parser.add_argument("--threads", type=int, default=20, help="Number of threads (default: 20)")
    args = parser.parse_args()

    target = args.url
    scan_type = args.scan
    threads = args.threads

    
    print(f"[+] Target: {target}")
    print(f"[+] Scan Mode: {scan_type}")
    print(f"[+] Output Report: results/report_{target.replace('.', '_')}.txt")
    print(f"[+] Threads: {threads}")
    print(f"[+] Verbose Mode: OFF\n")

    print("[*] Starting scan...\n")

    report = ReportGenerator(target)

    recon_lines = []
    port_lines = []
    vuln_lines = []
    web_lines = []

    # Recon
    if scan_type in ["recon", "all"]:
        recon_lines = capture_output(run_recon, target)
        print("\n".join(recon_lines))

    # Port Scan + CVE Lookup
    if scan_type in ["port", "all"]:
        port_results = run_port_scan(target, threads)
        if port_results:
            for port, service in port_results:
                port_line = f"Port {port} - {service}"
                port_lines.append(port_line)
                print(f"[OPEN] {port_line}")

                cve_output = capture_output(lookup_cves, f"{service} {port}")
                print("\n".join(cve_output))
                port_lines.extend(cve_output)
        else:
            port_lines.append("No open ports found.")
            print("[!] No open ports found.")

    # Vuln Scan
    if scan_type in ["vuln", "all"]:
        vuln_lines = capture_output(run_vuln_scan, target)
        print("\n".join(vuln_lines))

    # Web Scan
    if scan_type in ["web", "all"]:
        web_lines = capture_output(run_web_scan, target)
        print("\n".join(web_lines))

    # Add to report
    if recon_lines:
        report.add_section("Reconnaissance", recon_lines)
    if port_lines:
        report.add_section("Port Scan", port_lines)
    if vuln_lines:
        report.add_section("Vulnerability Scan", vuln_lines)
    if web_lines:
        report.add_section("Web Scan", web_lines)
    
    if scan_type in ["dir"]:
     dir_lines = capture_output(run_dir_bruteforce, target)
     print("\n".join(dir_lines))
     if dir_lines:
        report.add_section("Directory Bruteforce", dir_lines)

    report.save()

if __name__ == "__main__":
    main()

