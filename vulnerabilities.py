#!/usr/bin/env python3
"""
Basic Web Vulnerability Scanner (Beginner Version)
----------------------------------------------------
Checks a website for a few common, well-known security issues:
  1. Missing security headers
  2. SSL certificate expiry
  3. Basic reflected XSS
  4. Basic SQL injection error messages

⚠️ Only scan websites you own or have permission to test.

Usage:
    python basic_scanner.py https://example.com
"""

import sys
import ssl
import socket
from datetime import datetime
import requests

requests.packages.urllib3.disable_warnings()


def check_headers(url):
    print("\n[1] Checking security headers...")
    resp = requests.get(url, verify=False, timeout=5)
    headers = resp.headers

    important_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
    ]

    for header in important_headers:
        if header in headers:
            print(f"  [OK]      {header} is present")
        else:
            print(f"  [MISSING] {header} is missing")


def check_ssl_expiry(hostname):
    print("\n[2] Checking SSL certificate...")
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (expiry_date - datetime.utcnow()).days

        if days_left < 0:
            print("  [BAD] SSL certificate has expired!")
        elif days_left < 15:
            print(f"  [WARN] SSL certificate expires soon ({days_left} days left)")
        else:
            print(f"  [OK] SSL certificate valid for {days_left} more days")
    except Exception as e:
        print(f"  [SKIP] Could not check SSL: {e}")


def check_xss(url):
    print("\n[3] Checking basic reflected XSS...")
    payload = "<script>alert(1)</script>"
    test_url = url + "?q=" + payload
    try:
        resp = requests.get(test_url, verify=False, timeout=5)
        if payload in resp.text:
            print("  [VULNERABLE] Input is reflected back without escaping!")
        else:
            print("  [OK] Payload not reflected")
    except Exception as e:
        print(f"  [SKIP] Could not test XSS: {e}")


def check_sql_injection(url):
    print("\n[4] Checking basic SQL injection...")
    payload = "'"
    test_url = url + "?id=" + payload
    error_signs = ["sql syntax", "mysql", "sqlstate", "unclosed quotation"]
    try:
        resp = requests.get(test_url, verify=False, timeout=5)
        body = resp.text.lower()
        if any(sign in body for sign in error_signs):
            print("  [VULNERABLE] Database error message detected!")
        else:
            print("  [OK] No SQL error detected")
    except Exception as e:
        print(f"  [SKIP] Could not test SQL injection: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python basic_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith("http"):
        url = "https://" + url

    hostname = url.replace("https://", "").replace("http://", "").split("/")[0]

    print(f"Scanning: {url}")
    check_headers(url)
    check_ssl_expiry(hostname)
    check_xss(url)
    check_sql_injection(url)
    print("\nScan complete.")


if __name__ == "__main__":
    main()