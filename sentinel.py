#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Project Sentinel v2 - Professional Bug Hunter's Framework
# Author: Your Name / Ibar
# Features: Chaining, Output Saving, Advanced Vuln Checks

import requests
import socket
import argparse
import threading
import queue
import time
import os
import sys
import re
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Inisialisasi Colorama
init(autoreset=True)

# --- Banner ---
def print_banner():
    banner = """
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
    """
    print(f"{Fore.CYAN}{Style.BRIGHT}{banner}")
    print(f"{Fore.YELLOW}{'Professional Bug Hunter\'s Framework'.center(65)}")
    print(f"{Fore.RED}{'Use Responsibly. Think Ethically.'.center(65)}\n")

# =================================================================
# MODUL 1: ASSET & SUBDOMAIN DISCOVERY
# =================================================================
class SubdomainScanner:
    def __init__(self, domain, wordlist, threads=20, output_file=None):
        self.domain = domain
        self.wordlist = wordlist
        self.threads = threads
        self.output_file = output_file
        self.q = queue.Queue()
        self.found_subdomains = []

    def _bruteforce(self):
        while not self.q.empty():
            subdomain = self.q.get()
            full_domain = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                print(f"{Fore.GREEN}[+] Subdomain Ditemukan: {full_domain} ({ip})")
                self.found_subdomains.append(full_domain)
            except socket.gaierror:
                pass
            self.q.task_done()

    def run(self):
        print(f"\n{Fore.BLUE}[*] Memulai brute-force subdomain untuk {self.domain}...")
        if not os.path.exists(self.wordlist):
            print(f"{Fore.RED}[!] File wordlist tidak ditemukan: {self.wordlist}")
            return []

        with open(self.wordlist, 'r') as f:
            for line in f:
                self.q.put(line.strip())
        
        for _ in range(self.threads):
            t = threading.Thread(target=self._bruteforce, daemon=True)
            t.start()
        
        self.q.join()
        print(f"{Fore.GREEN}[+] Selesai. Ditemukan {len(self.found_subdomains)} subdomain.")

        if self.output_file:
            print(f"{Fore.CYAN}[*] Menyimpan hasil ke {self.output_file}...")
            with open(self.output_file, 'w') as f:
                for sub in self.found_subdomains:
                    f.write(f"{sub}\n")
        return self.found_subdomains

# =================================================================
# MODUL 2: CONTENT & ENDPOINT SCANNER
# =================================================================
# (Tidak ada perubahan signifikan, tetap powerful)
class ContentScanner:
    def __init__(self, base_url, wordlist, threads=20):
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.wordlist = wordlist
        self.threads = threads
        self.q = queue.Queue()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Sentinel-Scanner/2.0'})

    def _scan_path(self):
        while not self.q.empty():
            path = self.q.get()
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.get(url, timeout=7, allow_redirects=False)
                if 200 <= resp.status_code < 300:
                    print(f"{Fore.GREEN}[{resp.status_code}] Path Ditemukan: {url}")
                elif 300 <= resp.status_code < 400:
                    print(f"{Fore.YELLOW}[{resp.status_code}] Redirect: {url} -> {resp.headers.get('Location')}")
            except requests.RequestException:
                pass
            self.q.task_done()

    def run(self):
        print(f"\n{Fore.BLUE}[*] Memulai pemindaian konten di {self.base_url}...")
        if not os.path.exists(self.wordlist):
            print(f"{Fore.RED}[!] File wordlist tidak ditemukan: {self.wordlist}")
            return
        with open(self.wordlist, 'r') as f:
            for line in f:
                self.q.put(line.strip())
        for _ in range(self.threads):
            t = threading.Thread(target=self._scan_path, daemon=True)
            t.start()
        self.q.join()
        print(f"{Fore.GREEN}[+] Pemindaian konten selesai.")

# =================================================================
# MODUL 3: VULNERABILITY ANALYSIS (VERSI OVERPOWER)
# =================================================================
class VulnScanner:
    def __init__(self, target_url):
        self.url = target_url.strip()
        if not urlparse(self.url).scheme:
            self.url = 'http://' + self.url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Sentinel-Scanner/2.0'})

    def check_security_headers(self):
        print(f"\n{Fore.CYAN}--- Menganalisis Security Headers ---")
        try:
            resp = self.session.get(self.url, timeout=10)
            headers = resp.headers
            critical_headers = {'Content-Security-Policy': False, 'Strict-Transport-Security': False, 'X-Content-Type-Options': False, 'X-Frame-Options': False}
            for header in headers:
                if header in critical_headers: critical_headers[header] = True
            for header, found in critical_headers.items():
                status = f"{Fore.GREEN}[+] Ditemukan" if found else f"{Fore.RED}[!] TIDAK DITEMUKAN"
                print(f"{status}: {header}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Gagal mengambil headers: {e}")

    def check_subdomain_takeover(self):
        print(f"\n{Fore.CYAN}--- Mencari Potensi Subdomain Takeover ---")
        takeover_fingerprints = [
            "this shop is currently unavailable", "no such bucket", "repository not found", 
            "there isn't a github pages site here", "the specified bucket does not exist"
        ]
        try:
            resp = self.session.get(self.url, timeout=10)
            for fingerprint in takeover_fingerprints:
                if fingerprint.lower() in resp.text.lower():
                    print(f"{Fore.RED}[!!!] POTENSI SUBDOMAIN TAKEOVER: Ditemukan fingerprint '{fingerprint}' di {self.url}")
                    break
        except requests.RequestException:
            pass

    def find_secrets_in_js(self):
        print(f"\n{Fore.CYAN}--- Mencari Informasi Sensitif di File JavaScript ---")
        try:
            resp = self.session.get(self.url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            js_files = [urljoin(self.url, script['src']) for script in soup.find_all('script') if 'src' in script.attrs]
            
            secret_patterns = re.compile(r'(api_key|secret|token|password)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})[\'"]?', re.IGNORECASE)

            for js_file in js_files:
                try:
                    js_content = self.session.get(js_file, timeout=10).text
                    matches = secret_patterns.findall(js_content)
                    if matches:
                        for match in matches:
                            print(f"{Fore.RED}[!!!] POTENSI KEBOCORAN INFO: Ditemukan '{match[0]}' di {js_file}")
                except requests.RequestException:
                    continue
        except requests.RequestException:
            pass

    def run_all_checks(self):
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} MEMULAI ANALISIS KERENTANAN UNTUK: {self.url} {'='*20}")
        self.check_security_headers()
        self.check_subdomain_takeover()
        self.find_secrets_in_js()
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} ANALISIS KERENTANAN SELESAI {'='*38}")

# =================================================================
# MAIN FUNCTION & ARGUMENT PARSING
# =================================================================
def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()

    parser = argparse.ArgumentParser(description="Project Sentinel v2 - Professional Bug Hunter's Framework")
    subparsers = parser.add_subparsers(dest='mode', help='Pilih mode operasi')

    # Mode 1: Recon
    recon_parser = subparsers.add_parser('recon', help='Menemukan subdomain dan aset.')
    recon_parser.add_argument('-d', '--domain', required=True, help='Domain target (contoh: google.com)')
    recon_parser.add_argument('-w', '--wordlist', required=True, help='Path ke file wordlist subdomain.')
    recon_parser.add_argument('-t', '--threads', type=int, default=50, help='Jumlah threads (default: 50)')
    recon_parser.add_argument('-o', '--output', help='File untuk menyimpan hasil subdomain (contoh: subdomains.txt)')

    # Mode 2: Scan
    scan_parser = subparsers.add_parser('scan', help='Memindai direktori dan file.')
    scan_parser.add_argument('-u', '--url', required=True, help='URL target (contoh: https://google.com)')
    scan_parser.add_argument('-w', '--wordlist', required=True, help='Path ke file wordlist direktori.')
    scan_parser.add_argument('-t', '--threads', type=int, default=50, help='Jumlah threads (default: 50)')

    # Mode 3: Vuln
    vuln_parser = subparsers.add_parser('vuln', help='Menganalisis kerentanan umum.')
    vuln_parser.add_argument('-u', '--url', help='URL target tunggal.')
    vuln_parser.add_argument('-f', '--file', help='File berisi daftar URL/subdomain untuk dianalisis.')

    args = parser.parse_args()

    if args.mode == 'recon':
        scanner = SubdomainScanner(domain=args.domain, wordlist=args.wordlist, threads=args.threads, output_file=args.output)
        scanner.run()
    elif args.mode == 'scan':
        scanner = ContentScanner(base_url=args.url, wordlist=args.wordlist, threads=args.threads)
        scanner.run()
    elif args.mode == 'vuln':
        if args.url:
            scanner = VulnScanner(target_url=args.url)
            scanner.run_all_checks()
        elif args.file:
            if not os.path.exists(args.file):
                print(f"{Fore.RED}[!] File input tidak ditemukan: {args.file}")
                return
            with open(args.file, 'r') as f:
                for line in f:
                    scanner = VulnScanner(target_url=line.strip())
                    scanner.run_all_checks()
        else:
            print(f"{Fore.RED}[!] Anda harus menyediakan URL (-u) atau file (-f) untuk mode 'vuln'.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
