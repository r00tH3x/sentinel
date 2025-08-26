#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Project Sentinel v3 - Advanced OSINT & Reconnaissance Framework
# Author: Ibar
# Features: Enhanced OSINT, Multi-threading, Report Generation, API Integration

import requests
import socket
import argparse
import threading
import queue
import time
import os
import sys
import re
import json
import csv
import hashlib
import base64
import ssl
import dns.resolver
import whois
import shodan
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import random
import string

# Inisialisasi Colorama
init(autoreset=True)

# Configuration
CONFIG = {
    'SHODAN_API_KEY': '',  # Add your Shodan API key here
    'VIRUSTOTAL_API_KEY': '',  # Add your VirusTotal API key here
    'HUNTER_API_KEY': '',  # Add your Hunter.io API key here
    'SECURITYTRAILS_API_KEY': '',  # Add your SecurityTrails API key here
    'WAYBACK_MACHINE_API': '',  # Wayback Machine CDX API (free)
    'MAX_THREADS': 100,
    'TIMEOUT': 10,
    'USER_AGENTS': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0'
    ]
}

# Built-in wordlists
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
    'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mx', 'test', 'api', 'admin', 'blog',
    'dev', 'staging', 'portal', 'app', 'beta', 'cdn', 'shop', 'store', 'secure', 'vpn',
    'remote', 'mobile', 'jenkins', 'gitlab', 'github', 'bitbucket', 'support', 'help',
    'docs', 'forum', 'wiki', 'careers', 'jobs', 'marketing', 'sales', 'crm', 'erp',
    'dashboard', 'monitor', 'status', 'stats', 'analytics', 'metrics', 'logs', 'backup',
    'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elastic', 'kibana',
    'grafana', 'prometheus', 'consul', 'vault', 'nomad', 'docker', 'k8s', 'kubernetes',
    'rancher', 'harbor', 'registry', 'nexus', 'artifactory', 'sonar', 'quality',
    'ci', 'cd', 'build', 'deploy', 'release', 'staging', 'prod', 'production',
    'demo', 'sandbox', 'playground', 'training', 'education', 'academy', 'learn'
]

DIRECTORY_WORDLIST = [
    'admin', 'administrator', 'wp-admin', 'login', 'test', 'api', 'v1', 'v2',
    'backup', 'backups', 'old', 'temp', 'tmp', 'cache', 'config', 'configuration',
    'setup', 'install', 'installation', 'upgrade', 'update', 'maintenance',
    'debug', 'logs', 'log', 'error', 'errors', 'exception', 'exceptions',
    'db', 'database', 'sql', 'mysql', 'postgres', 'mongo', 'redis',
    'upload', 'uploads', 'files', 'file', 'download', 'downloads',
    'images', 'img', 'pics', 'pictures', 'photos', 'media', 'assets',
    'js', 'css', 'fonts', 'icons', 'favicon', 'robots.txt', 'sitemap.xml',
    'phpinfo', 'info', 'status', 'health', 'ping', 'version',
    'git', '.git', 'svn', '.svn', 'hg', '.hg', 'bzr', '.bzr',
    'env', '.env', 'config.php', 'config.json', 'web.config', 'app.config',
    'package.json', 'composer.json', 'Gemfile', 'requirements.txt',
    'Dockerfile', 'docker-compose.yml', '.dockerignore',
    'swagger', 'docs', 'documentation', 'readme', 'changelog',
    'manifest.json', 'service-worker.js', '.well-known'
]

# --- Enhanced Banner ---
def print_banner():
    banner = """
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗          ██╗   ██╗██████╗ 
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║          ██║   ██║╚════██╗
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║          ██║   ██║ █████╔╝
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║          ╚██╗ ██╔╝ ╚═══██╗
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗      ╚████╔╝ ██████╔╝
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝       ╚═══╝  ╚═════╝ 
    """
    print(f"{Fore.CYAN}{Style.BRIGHT}{banner}")
    print(f"{Fore.YELLOW}{'Advanced OSINT & Reconnaissance Framework'.center(80)}")
    print(f"{Fore.RED}{'Use Responsibly. Think Ethically.'.center(80)}")
    print(f"{Fore.GREEN}{'Enhanced with API Integration & Advanced Features'.center(80)}\n")

# =================================================================
# UTILITY CLASSES
# =================================================================
class Logger:
    def __init__(self, output_dir="sentinel_output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def save_json(self, data, filename):
        filepath = os.path.join(self.output_dir, f"{filename}_{self.timestamp}.json")
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] Results saved to: {filepath}")
        
    def save_csv(self, data, filename, headers):
        filepath = os.path.join(self.output_dir, f"{filename}_{self.timestamp}.csv")
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f"{Fore.GREEN}[+] Results saved to: {filepath}")
        
    def save_txt(self, data, filename):
        filepath = os.path.join(self.output_dir, f"{filename}_{self.timestamp}.txt")
        with open(filepath, 'w') as f:
            f.write('\n'.join(data))
        print(f"{Fore.GREEN}[+] Results saved to: {filepath}")

class APIClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['USER_AGENTS'])
        })
        
    def shodan_search(self, query):
        if not CONFIG['SHODAN_API_KEY']:
            return []
        try:
            api = shodan.Shodan(CONFIG['SHODAN_API_KEY'])
            results = api.search(query)
            return results['matches']
        except Exception as e:
            print(f"{Fore.RED}[!] Shodan API Error: {e}")
            return []
            
    def virustotal_domain(self, domain):
        if not CONFIG['VIRUSTOTAL_API_KEY']:
            return {}
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': CONFIG['VIRUSTOTAL_API_KEY'], 'domain': domain}
            resp = self.session.get(url, params=params)
            return resp.json()
        except Exception as e:
            print(f"{Fore.RED}[!] VirusTotal API Error: {e}")
            return {}
            
    def securitytrails_subdomains(self, domain):
        if not CONFIG['SECURITYTRAILS_API_KEY']:
            return []
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {'APIKEY': CONFIG['SECURITYTRAILS_API_KEY']}
            resp = self.session.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                subdomains = []
                for sub in data.get('subdomains', []):
                    subdomains.append(f"{sub}.{domain}")
                return subdomains
        except Exception as e:
            print(f"{Fore.RED}[!] SecurityTrails API Error: {e}")
            return []
            
    def hunter_io_emails(self, domain):
        if not CONFIG['HUNTER_API_KEY']:
            return []
        try:
            url = f"https://api.hunter.io/v2/domain-search"
            params = {
                'domain': domain,
                'api_key': CONFIG['HUNTER_API_KEY'],
                'limit': 100
            }
            resp = self.session.get(url, params=params, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                emails = []
                if 'data' in data and 'emails' in data['data']:
                    for email_data in data['data']['emails']:
                        email = email_data.get('value')
                        if email:
                            emails.append(email)
                return emails
        except Exception as e:
            print(f"{Fore.RED}[!] Hunter.io API Error: {e}")
            return []
            
    def rapid_dns_api(self, domain):
        """Free RapidDNS API untuk subdomain discovery"""
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            headers = {
                'User-Agent': random.choice(CONFIG['USER_AGENTS']),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            resp = self.session.get(url, headers=headers, timeout=15)
            
            if resp.status_code == 200:
                subdomains = []
                # Parse HTML response
                soup = BeautifulSoup(resp.text, 'html.parser')
                for row in soup.find_all('tr'):
                    cells = row.find_all('td')
                    if len(cells) >= 1:
                        subdomain = cells[0].get_text().strip()
                        if subdomain and subdomain.endswith(f".{domain}") and subdomain != domain:
                            subdomains.append(subdomain)
                return list(set(subdomains))  # Remove duplicates
        except Exception as e:
            print(f"{Fore.RED}[!] RapidDNS API Error: {e}")
            return []
            
    def alienvault_otx(self, domain):
        """AlienVault OTX - Free threat intelligence"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = self.session.get(url, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                subdomains = []
                for record in data.get('passive_dns', []):
                    hostname = record.get('hostname', '')
                    if hostname and hostname.endswith(f".{domain}") and hostname != domain:
                        subdomains.append(hostname)
                return list(set(subdomains))
        except Exception as e:
            print(f"{Fore.RED}[!] AlienVault OTX Error: {e}")
            return []
            
    def threatcrowd_api(self, domain):
        """ThreatCrowd API - Free"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/"
            params = {'domain': domain}
            resp = self.session.get(url, params=params, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                subdomains = data.get('subdomains', [])
                return [f"{sub}.{domain}" if not sub.endswith(f".{domain}") else sub for sub in subdomains]
        except Exception as e:
            print(f"{Fore.RED}[!] ThreatCrowd API Error: {e}")
            return []

# =================================================================
# ENHANCED SUBDOMAIN DISCOVERY
# =================================================================
class EnhancedSubdomainScanner:
    def __init__(self, domain, threads=50, use_wordlist=True, use_dns=True, use_crt=True, use_api=True):
        self.domain = domain
        self.threads = threads
        self.use_wordlist = use_wordlist
        self.use_dns = use_dns
        self.use_crt = use_crt
        self.use_api = use_api
        self.found_subdomains = set()
        self.logger = Logger()
        self.api_client = APIClient()
        
    def _dns_bruteforce(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        try:
            result = dns.resolver.resolve(full_domain, 'A')
            ips = [str(ip) for ip in result]
            print(f"{Fore.GREEN}[+] Subdomain: {full_domain} -> {', '.join(ips)}")
            self.found_subdomains.add(full_domain)
            return {'subdomain': full_domain, 'ips': ips, 'method': 'dns_bruteforce'}
        except:
            return None
            
    def _crt_sh_search(self):
        print(f"{Fore.BLUE}[*] Searching certificate transparency logs...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = self.api_client.session.get(url, timeout=30)
            if resp.status_code == 200:
                certs = resp.json()
                for cert in certs:
                    name = cert.get('name_value', '').strip()
                    if name and not name.startswith('*'):
                        self.found_subdomains.add(name)
                        print(f"{Fore.GREEN}[+] Certificate: {name}")
        except Exception as e:
            print(f"{Fore.RED}[!] crt.sh error: {e}")
            
    def _dns_dumpster(self):
        print(f"{Fore.BLUE}[*] Querying DNSDumpster...")
        try:
            url = "https://dnsdumpster.com/"
            session = requests.Session()
            resp = session.get(url)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf_token = soup.find('input', {'name': 'csrfmiddlewaretoken'})['value']
            
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain,
                'user': 'free'
            }
            resp = session.post(url, data=data)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Parse results
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 1:
                    subdomain = cells[0].get_text().strip()
                    if subdomain.endswith(f".{self.domain}"):
                        self.found_subdomains.add(subdomain)
                        print(f"{Fore.GREEN}[+] DNSDumpster: {subdomain}")
        except Exception as e:
            print(f"{Fore.RED}[!] DNSDumpster error: {e}")
            
    def _google_dorking(self):
        print(f"{Fore.BLUE}[*] Google dorking for subdomains...")
        queries = [
            f"site:{self.domain}",
            f"site:*.{self.domain}",
            f"inurl:{self.domain}",
        ]
        
        for query in queries:
            try:
                url = f"https://www.google.com/search?q={quote(query)}&num=100"
                resp = self.api_client.session.get(url, timeout=10)
                
                # Extract domains from results
                pattern = rf'([a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(self.domain)})'
                matches = re.findall(pattern, resp.text)
                for match in matches:
                    self.found_subdomains.add(match)
                    print(f"{Fore.GREEN}[+] Google: {match}")
                    
                time.sleep(random.uniform(2, 5))  # Rate limiting
            except Exception as e:
                print(f"{Fore.RED}[!] Google dorking error: {e}")
                
    def _wayback_machine(self):
        print(f"{Fore.BLUE}[*] Searching Wayback Machine...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}&output=json&collapse=urlkey"
            resp = self.api_client.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for item in data[1:]:  # Skip header
                    if len(item) > 2:
                        archived_url = item[2]
                        domain_match = re.search(rf'([a-zA-Z0-9][a-zA-Z0-9\-]*\.{re.escape(self.domain)})', archived_url)
                        if domain_match:
                            subdomain = domain_match.group(1)
                            self.found_subdomains.add(subdomain)
                            print(f"{Fore.GREEN}[+] Wayback: {subdomain}")
        except Exception as e:
            print(f"{Fore.RED}[!] Wayback Machine error: {e}")
    
    def run(self):
        print(f"\n{Fore.MAGENTA}{'='*20} ENHANCED SUBDOMAIN DISCOVERY FOR: {self.domain} {'='*20}")
        
        results = []
        
        # Certificate Transparency
        if self.use_crt:
            self._crt_sh_search()
            
    def _securitytrails_search(self):
        print(f"{Fore.BLUE}[*] Searching SecurityTrails API...")
        subdomains = self.api_client.securitytrails_subdomains(self.domain)
        for subdomain in subdomains:
            self.found_subdomains.add(subdomain)
            print(f"{Fore.GREEN}[+] SecurityTrails: {subdomain}")
            
    def _free_api_sources(self):
        """Multiple free API sources for subdomain discovery"""
        print(f"{Fore.BLUE}[*] Querying free API sources...")
        
        # RapidDNS
        rapid_subs = self.api_client.rapid_dns_api(self.domain)
        for sub in rapid_subs:
            self.found_subdomains.add(sub)
            print(f"{Fore.GREEN}[+] RapidDNS: {sub}")
            
        # AlienVault OTX
        otx_subs = self.api_client.alienvault_otx(self.domain)
        for sub in otx_subs:
            self.found_subdomains.add(sub)
            print(f"{Fore.GREEN}[+] OTX: {sub}")
            
        # ThreatCrowd
        tc_subs = self.api_client.threatcrowd_api(self.domain)
        for sub in tc_subs:
            self.found_subdomains.add(sub)
            print(f"{Fore.GREEN}[+] ThreatCrowd: {sub}")
            
    def _hackertarget_api(self):
        """HackerTarget free API"""
        print(f"{Fore.BLUE}[*] Querying HackerTarget API...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = self.api_client.session.get(url, timeout=15)
            
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and subdomain.endswith(f".{self.domain}"):
                            self.found_subdomains.add(subdomain)
                            print(f"{Fore.GREEN}[+] HackerTarget: {subdomain}")
        except Exception as e:
            print(f"{Fore.RED}[!] HackerTarget API Error: {e}")
            
    def _sublist3r_sources(self):
        """Implement some Sublist3r-like sources"""
        print(f"{Fore.BLUE}[*] Searching additional sources...")
        
        sources = [
            f"https://sonar.omnisint.io/subdomains/{self.domain}",
            f"https://riddler.io/search/exportcsv?q=pld:{self.domain}",
        ]
        
        for source in sources:
            try:
                resp = self.api_client.session.get(source, timeout=10)
                if resp.status_code == 200:
                    # Extract subdomains using regex
                    pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)*{re.escape(self.domain)}'
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    for match in matches:
                        subdomain = match[0] if isinstance(match, tuple) else match
                        if subdomain and subdomain != self.domain:
                            self.found_subdomains.add(subdomain)
                            print(f"{Fore.GREEN}[+] Additional: {subdomain}")
            except Exception as e:
                continue
        
        # DNS Bruteforce
        if self.use_wordlist:
            print(f"{Fore.BLUE}[*] Starting DNS bruteforce with {len(SUBDOMAIN_WORDLIST)} words...")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._dns_bruteforce, sub): sub for sub in SUBDOMAIN_WORDLIST}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
        
        # Validate all found subdomains
        print(f"{Fore.BLUE}[*] Validating discovered subdomains...")
        valid_subdomains = []
        for subdomain in self.found_subdomains:
            try:
                ips = socket.gethostbyname_ex(subdomain)[2]
                valid_subdomains.append({'subdomain': subdomain, 'ips': ips})
            except:
                pass
        
        print(f"\n{Fore.GREEN}[+] Total valid subdomains found: {len(valid_subdomains)}")
        
        # Save results
        self.logger.save_json(valid_subdomains, "subdomains")
        self.logger.save_txt([sub['subdomain'] for sub in valid_subdomains], "subdomains_list")
        
        return valid_subdomains

# =================================================================
# ENHANCED CONTENT DISCOVERY
# =================================================================
class EnhancedContentScanner:
    def __init__(self, base_url, threads=50, check_status_codes=True, find_backups=True):
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.threads = threads
        self.check_status_codes = check_status_codes
        self.find_backups = find_backups
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['USER_AGENTS'])
        })
        self.found_paths = []
        self.logger = Logger()
        
    def _scan_path(self, path):
        url = urljoin(self.base_url, path)
        try:
            resp = self.session.get(url, timeout=CONFIG['TIMEOUT'], allow_redirects=False)
            
            result = {
                'url': url,
                'status_code': resp.status_code,
                'content_length': len(resp.content),
                'content_type': resp.headers.get('Content-Type', ''),
                'server': resp.headers.get('Server', ''),
                'last_modified': resp.headers.get('Last-Modified', ''),
                'location': resp.headers.get('Location', '') if resp.is_redirect else ''
            }
            
            if 200 <= resp.status_code < 300:
                print(f"{Fore.GREEN}[{resp.status_code}] Found: {url} ({len(resp.content)} bytes)")
                self.found_paths.append(result)
            elif 300 <= resp.status_code < 400:
                print(f"{Fore.YELLOW}[{resp.status_code}] Redirect: {url} -> {result['location']}")
                self.found_paths.append(result)
            elif resp.status_code == 403:
                print(f"{Fore.CYAN}[{resp.status_code}] Forbidden: {url}")
                self.found_paths.append(result)
            elif self.check_status_codes and resp.status_code in [401, 500, 503]:
                print(f"{Fore.MAGENTA}[{resp.status_code}] Interesting: {url}")
                self.found_paths.append(result)
                
            return result
        except requests.RequestException:
            return None
            
    def _generate_backup_paths(self, base_paths):
        backup_extensions = ['.bak', '.backup', '.old', '.orig', '.save', '.tmp', '~', '.copy']
        backup_prefixes = ['backup_', 'old_', 'copy_', 'bak_']
        backup_suffixes = ['_backup', '_old', '_copy', '_bak', '_orig']
        
        backup_paths = []
        for path in base_paths:
            # Extension-based backups
            for ext in backup_extensions:
                backup_paths.append(path + ext)
            
            # Prefix-based backups
            for prefix in backup_prefixes:
                backup_paths.append(prefix + path)
                
            # Suffix-based backups
            for suffix in backup_suffixes:
                if '.' in path:
                    name, ext = path.rsplit('.', 1)
                    backup_paths.append(f"{name}{suffix}.{ext}")
                else:
                    backup_paths.append(path + suffix)
        
        return backup_paths
    
    def _check_common_files(self):
        common_files = [
            'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
            '.htaccess', '.htpasswd', 'web.config', '.DS_Store', 'thumbs.db',
            'phpinfo.php', 'info.php', 'test.php', 'phpMyAdmin/',
            '.git/config', '.svn/entries', '.env', 'config.php', 'wp-config.php',
            'README.md', 'CHANGELOG.md', 'LICENSE', 'package.json', 'composer.json'
        ]
        
        print(f"{Fore.BLUE}[*] Checking common sensitive files...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_path, path): path for path in common_files}
            for future in as_completed(futures):
                future.result()
    
    def run(self):
        print(f"\n{Fore.MAGENTA}{'='*20} ENHANCED CONTENT DISCOVERY FOR: {self.base_url} {'='*20}")
        
        # Check common files first
        self._check_common_files()
        
        # Main directory bruteforce
        print(f"{Fore.BLUE}[*] Starting directory bruteforce with {len(DIRECTORY_WORDLIST)} words...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_path, path): path for path in DIRECTORY_WORDLIST}
            for future in as_completed(futures):
                future.result()
        
        # Check for backup files if enabled
        if self.find_backups and self.found_paths:
            print(f"{Fore.BLUE}[*] Checking for backup files...")
            found_paths_names = [urlparse(p['url']).path.lstrip('/') for p in self.found_paths if p['status_code'] == 200]
            backup_paths = self._generate_backup_paths(found_paths_names)
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._scan_path, path): path for path in backup_paths[:100]}  # Limit to prevent spam
                for future in as_completed(futures):
                    future.result()
        
        print(f"\n{Fore.GREEN}[+] Total paths discovered: {len(self.found_paths)}")
        
        # Save results
        self.logger.save_json(self.found_paths, "content_discovery")
        self.logger.save_csv(self.found_paths, "content_discovery", 
                           ['url', 'status_code', 'content_length', 'content_type', 'server', 'last_modified', 'location'])
        
        return self.found_paths

# =================================================================
# ENHANCED VULNERABILITY SCANNER
# =================================================================
class EnhancedVulnScanner:
    def __init__(self, target_url):
        self.url = target_url.strip()
        if not urlparse(self.url).scheme:
            self.url = 'http://' + self.url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['USER_AGENTS'])
        })
        self.vulnerabilities = []
        self.logger = Logger()
        
    def _check_ssl_tls(self):
        print(f"\n{Fore.CYAN}--- SSL/TLS Security Analysis ---")
        try:
            parsed_url = urlparse(self.url)
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                with socket.create_connection((parsed_url.hostname, parsed_url.port or 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=parsed_url.hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        
                        print(f"{Fore.GREEN}[+] SSL Certificate Subject: {cert.get('subject')}")
                        print(f"{Fore.GREEN}[+] SSL Certificate Issuer: {cert.get('issuer')}")
                        print(f"{Fore.GREEN}[+] SSL Certificate Valid Until: {cert.get('notAfter')}")
                        print(f"{Fore.GREEN}[+] Cipher Suite: {cipher}")
                        
                        # Check for weak ciphers
                        if cipher and ('RC4' in cipher[0] or 'DES' in cipher[0] or 'MD5' in cipher[0]):
                            vuln = {
                                'type': 'Weak Cipher Suite',
                                'severity': 'Medium',
                                'description': f'Weak cipher detected: {cipher[0]}',
                                'url': self.url
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[!] VULNERABILITY: Weak cipher suite detected")
            else:
                vuln = {
                    'type': 'No HTTPS',
                    'severity': 'Medium',
                    'description': 'Website does not use HTTPS encryption',
                    'url': self.url
                }
                self.vulnerabilities.append(vuln)
                print(f"{Fore.RED}[!] VULNERABILITY: No HTTPS encryption")
        except Exception as e:
            print(f"{Fore.RED}[!] SSL/TLS check failed: {e}")
    
    def _check_security_headers(self):
        print(f"\n{Fore.CYAN}--- Security Headers Analysis ---")
        try:
            resp = self.session.get(self.url, timeout=CONFIG['TIMEOUT'])
            headers = resp.headers
            
            security_headers = {
                'Content-Security-Policy': 'CSP header missing - XSS protection',
                'Strict-Transport-Security': 'HSTS header missing - MITM attacks possible',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-XSS-Protection': 'XSS protection header missing',
                'Referrer-Policy': 'Referrer policy not set',
                'Permissions-Policy': 'Feature policy not configured'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    print(f"{Fore.GREEN}[+] {header}: {headers[header]}")
                else:
                    vuln = {
                        'type': f'Missing Security Header: {header}',
                        'severity': 'Low' if header in ['Referrer-Policy', 'Permissions-Policy'] else 'Medium',
                        'description': description,
                        'url': self.url
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] MISSING: {header} - {description}")
                    
            # Check for dangerous headers
            dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in dangerous_headers:
                if header in headers:
                    vuln = {
                        'type': f'Information Disclosure: {header}',
                        'severity': 'Low',
                        'description': f'Server information exposed: {headers[header]}',
                        'url': self.url
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.YELLOW}[!] INFO DISCLOSURE: {header}: {headers[header]}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Failed to fetch headers: {e}")
    
    def _check_subdomain_takeover(self):
        print(f"\n{Fore.CYAN}--- Subdomain Takeover Check ---")
        takeover_signatures = {
            'github.io': ["There isn't a GitHub Pages site here.", "For root URLs"],
            'herokuapp.com': ["No such app", "heroku"],
            'amazonaws.com': ["NoSuchBucket", "The specified bucket does not exist"],
            'shopify.com': ["Sorry, this shop is currently unavailable"],
            'fastly.com': ["Fastly error: unknown domain"],
            'feedpress.me': ["The feed has not been found"],
            'ghost.io': ["The thing you were looking for is no longer here"],
            'helpjuice.com': ["We could not find what you're looking for"],
            'helpscout.net': ["No settings were found for this company ID"],
            'surge.sh': ["project not found"],
            'bitbucket.io': ["Repository not found"],
            'uservoice.com': ["This UserVoice subdomain is currently available"],
            'statuspage.io': ["You are being redirected", "statuspage"]
        }
        
        try:
            resp = self.session.get(self.url, timeout=CONFIG['TIMEOUT'])
            content = resp.text.lower()
            
            for service, signatures in takeover_signatures.items():
                if any(sig.lower() in content for sig in signatures):
                    vuln = {
                        'type': 'Subdomain Takeover',
                        'severity': 'High',
                        'description': f'Potential subdomain takeover detected for {service}',
                        'url': self.url,
                        'evidence': signatures[0]
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] CRITICAL: Potential subdomain takeover - {service}")
                    return
                    
            print(f"{Fore.GREEN}[+] No subdomain takeover vulnerabilities detected")
        except requests.RequestException:
            print(f"{Fore.RED}[!] Could not check subdomain takeover")
    
    def _find_secrets_in_source(self):
        print(f"\n{Fore.CYAN}--- Source Code Secret Analysis ---")
        try:
            resp = self.session.get(self.url, timeout=CONFIG['TIMEOUT'])
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Get all script sources
            js_urls = []
            for script in soup.find_all('script'):
                if script.get('src'):
                    js_urls.append(urljoin(self.url, script.get('src')))
            
            # Add inline scripts
            js_urls.append(self.url)  # Main page
            
            secret_patterns = {
                'api_key': re.compile(r'api[_\-\s]*key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})', re.IGNORECASE),
                'secret_key': re.compile(r'secret[_\-\s]*key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})', re.IGNORECASE),
                'access_token': re.compile(r'access[_\-\s]*token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})', re.IGNORECASE),
                'auth_token': re.compile(r'auth[_\-\s]*token[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{16,})', re.IGNORECASE),
                'password': re.compile(r'password[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_@#$%^&*]{8,})', re.IGNORECASE),
                'private_key': re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----'),
                'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
                'slack_token': re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'),
                'github_token': re.compile(r'ghp_[0-9a-zA-Z]{36}'),
                'jwt_token': re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'),
                'database_url': re.compile(r'(mongodb|mysql|postgres)://[a-zA-Z0-9\-_.]+:[a-zA-Z0-9\-_.]+@[a-zA-Z0-9\-_.]+', re.IGNORECASE)
            }
            
            for js_url in js_urls[:10]:  # Limit to prevent spam
                try:
                    if js_url == self.url:
                        content = resp.text
                        source = "Main Page"
                    else:
                        js_resp = self.session.get(js_url, timeout=CONFIG['TIMEOUT'])
                        content = js_resp.text
                        source = js_url
                    
                    for secret_type, pattern in secret_patterns.items():
                        matches = pattern.findall(content)
                        for match in matches:
                            secret_value = match if isinstance(match, str) else match[0] if match else "Found"
                            vuln = {
                                'type': f'Secret Exposure: {secret_type}',
                                'severity': 'High' if secret_type in ['private_key', 'aws_key'] else 'Medium',
                                'description': f'{secret_type} found in source code',
                                'url': source,
                                'evidence': secret_value[:20] + "..." if len(secret_value) > 20 else secret_value
                            }
                            self.vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[!!!] SECRET FOUND: {secret_type} in {source}")
                            
                except requests.RequestException:
                    continue
                    
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Failed to analyze source code: {e}")
    
    def _check_common_vulns(self):
        print(f"\n{Fore.CYAN}--- Common Web Vulnerabilities ---")
        
        # SQL Injection Test
        sqli_payloads = ["'", "1'OR'1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]
        print(f"{Fore.BLUE}[*] Testing for SQL Injection...")
        
        try:
            for payload in sqli_payloads:
                test_url = f"{self.url}?id={payload}"
                resp = self.session.get(test_url, timeout=CONFIG['TIMEOUT'])
                
                sqli_errors = [
                    "sql syntax", "mysql_fetch", "ORA-01756", "Microsoft OLE DB Provider",
                    "PostgreSQL query failed", "SQLite/JDBCDriver", "SQLServer JDBC Driver"
                ]
                
                for error in sqli_errors:
                    if error.lower() in resp.text.lower():
                        vuln = {
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'description': f'Potential SQL injection detected with payload: {payload}',
                            'url': test_url,
                            'evidence': error
                        }
                        self.vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!!!] CRITICAL: SQL Injection vulnerability detected")
                        break
        except:
            pass
        
        # XSS Test
        print(f"{Fore.BLUE}[*] Testing for Cross-Site Scripting (XSS)...")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        try:
            for payload in xss_payloads:
                test_url = f"{self.url}?q={payload}"
                resp = self.session.get(test_url, timeout=CONFIG['TIMEOUT'])
                
                if payload in resp.text:
                    vuln = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'Reflected XSS vulnerability detected with payload: {payload}',
                        'url': test_url,
                        'evidence': 'Payload reflected in response'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] CRITICAL: XSS vulnerability detected")
                    break
        except:
            pass
        
        # Directory Traversal Test
        print(f"{Fore.BLUE}[*] Testing for Directory Traversal...")
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        try:
            for payload in traversal_payloads:
                test_url = f"{self.url}?file={payload}"
                resp = self.session.get(test_url, timeout=CONFIG['TIMEOUT'])
                
                if "root:x:" in resp.text or "[fonts]" in resp.text:
                    vuln = {
                        'type': 'Directory Traversal',
                        'severity': 'High',
                        'description': f'Directory traversal vulnerability detected with payload: {payload}',
                        'url': test_url,
                        'evidence': 'System files accessible'
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!!!] CRITICAL: Directory Traversal vulnerability detected")
                    break
        except:
            pass
    
    def _check_cms_specific(self):
        print(f"\n{Fore.CYAN}--- CMS-Specific Vulnerability Checks ---")
        
        try:
            resp = self.session.get(self.url, timeout=CONFIG['TIMEOUT'])
            content = resp.text.lower()
            
            # WordPress Detection and Checks
            if 'wp-content' in content or 'wordpress' in content:
                print(f"{Fore.YELLOW}[*] WordPress detected, running specific checks...")
                
                wp_checks = [
                    '/wp-admin/',
                    '/wp-login.php',
                    '/wp-config.php',
                    '/wp-content/uploads/',
                    '/wp-includes/',
                    '/readme.html',
                    '/wp-admin/install.php',
                    '/?author=1'  # User enumeration
                ]
                
                for check in wp_checks:
                    try:
                        check_url = urljoin(self.url, check)
                        resp = self.session.get(check_url, timeout=5)
                        
                        if resp.status_code == 200:
                            if 'wp-login' in check and 'login' in resp.text.lower():
                                vuln = {
                                    'type': 'WordPress Login Page Accessible',
                                    'severity': 'Medium',
                                    'description': 'WordPress login page is accessible without protection',
                                    'url': check_url
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"{Fore.YELLOW}[!] WordPress login page accessible: {check_url}")
                                
                            elif 'readme.html' in check:
                                vuln = {
                                    'type': 'Information Disclosure',
                                    'severity': 'Low',
                                    'description': 'WordPress readme file accessible',
                                    'url': check_url
                                }
                                self.vulnerabilities.append(vuln)
                                print(f"{Fore.YELLOW}[!] WordPress readme accessible: {check_url}")
                    except:
                        continue
            
            # Joomla Detection
            if 'joomla' in content or '/administrator/' in content:
                print(f"{Fore.YELLOW}[*] Joomla detected")
                joomla_checks = ['/administrator/', '/configuration.php']
                for check in joomla_checks:
                    try:
                        check_url = urljoin(self.url, check)
                        resp = self.session.get(check_url, timeout=5)
                        if resp.status_code == 200 and 'administrator' in check:
                            print(f"{Fore.YELLOW}[!] Joomla admin panel accessible: {check_url}")
                    except:
                        continue
            
            # Drupal Detection
            if 'drupal' in content or '/sites/default/' in content:
                print(f"{Fore.YELLOW}[*] Drupal detected")
                
        except requests.RequestException:
            pass
    
    def _technology_detection(self):
        print(f"\n{Fore.CYAN}--- Technology Stack Detection ---")
        
        try:
            resp = self.session.get(self.url, timeout=CONFIG['TIMEOUT'])
            headers = resp.headers
            content = resp.text.lower()
            
            technologies = {}
            
            # Server detection
            server = headers.get('Server', 'Unknown')
            technologies['Web Server'] = server
            print(f"{Fore.GREEN}[+] Web Server: {server}")
            
            # Framework detection
            frameworks = {
                'Laravel': ['laravel_session', 'laravel_token'],
                'Django': ['django', 'csrfmiddlewaretoken'],
                'Rails': ['authenticity_token', '_csrf_token'],
                'Spring': ['spring', 'jsessionid'],
                'Express': ['express', 'connect.sid'],
                'Flask': ['flask', 'session'],
                'ASP.NET': ['__viewstate', 'asp.net'],
                'PHP': ['phpsessid', '<?php']
            }
            
            for framework, indicators in frameworks.items():
                if any(indicator in content for indicator in indicators):
                    technologies['Framework'] = framework
                    print(f"{Fore.GREEN}[+] Framework: {framework}")
                    break
            
            # Database detection (from errors or patterns)
            databases = {
                'MySQL': ['mysql', 'phpmyadmin'],
                'PostgreSQL': ['postgresql', 'postgres'],
                'MongoDB': ['mongodb', 'mongo'],
                'SQLite': ['sqlite'],
                'Oracle': ['oracle', 'ora-']
            }
            
            for db, indicators in databases.items():
                if any(indicator in content for indicator in indicators):
                    technologies['Database'] = db
                    print(f"{Fore.GREEN}[+] Database: {db}")
                    break
            
            return technologies
            
        except requests.RequestException:
            return {}
    
    def run_all_checks(self):
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} ENHANCED VULNERABILITY ANALYSIS FOR: {self.url} {'='*20}")
        
        # Technology detection first
        technologies = self._technology_detection()
        
        # Run all vulnerability checks
        self._check_ssl_tls()
        self._check_security_headers()
        self._check_subdomain_takeover()
        self._find_secrets_in_source()
        self._check_common_vulns()
        self._check_cms_specific()
        
        # Summary
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}--- VULNERABILITY SUMMARY ---")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No vulnerabilities detected!")
        else:
            severity_count = {'High': 0, 'Medium': 0, 'Low': 0}
            for vuln in self.vulnerabilities:
                severity_count[vuln['severity']] += 1
            
            print(f"{Fore.RED}[!] Total Vulnerabilities: {len(self.vulnerabilities)}")
            print(f"{Fore.RED}[!] High: {severity_count['High']}")
            print(f"{Fore.YELLOW}[!] Medium: {severity_count['Medium']}")
            print(f"{Fore.CYAN}[!] Low: {severity_count['Low']}")
            
            # Save results
            report_data = {
                'target': self.url,
                'scan_timestamp': datetime.now().isoformat(),
                'technologies': technologies,
                'vulnerabilities': self.vulnerabilities,
                'summary': {
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'severity_breakdown': severity_count
                }
            }
            
            self.logger.save_json(report_data, "vulnerability_report")
            
            # Generate simple HTML report
            self._generate_html_report(report_data)
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} VULNERABILITY ANALYSIS COMPLETE {'='*38}")
        return self.vulnerabilities
    
    def _generate_html_report(self, report_data):
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sentinel v3 - Vulnerability Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .summary { background-color: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                .vulnerability { background-color: white; margin: 10px 0; padding: 15px; border-left: 5px solid #e74c3c; border-radius: 3px; }
                .high { border-left-color: #e74c3c; }
                .medium { border-left-color: #f39c12; }
                .low { border-left-color: #3498db; }
                .tech-info { background-color: #ecf0f1; padding: 10px; border-radius: 3px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ Sentinel v3 - Security Report</h1>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Scan Date:</strong> {scan_date}</p>
            </div>
            
            <div class="summary">
                <h2>📊 Summary</h2>
                <p><strong>Total Vulnerabilities:</strong> {total_vulns}</p>
                <p><strong>High Severity:</strong> {high_count} | <strong>Medium:</strong> {medium_count} | <strong>Low:</strong> {low_count}</p>
                
                <div class="tech-info">
                    <h3>🔧 Technology Stack</h3>
                    {tech_stack}
                </div>
            </div>
            
            <div class="vulnerabilities">
                <h2>🚨 Vulnerabilities</h2>
                {vulnerabilities}
            </div>
        </body>
        </html>
        """
        
        # Format technology stack
        tech_stack = ""
        for tech_type, tech_name in report_data['technologies'].items():
            tech_stack += f"<p><strong>{tech_type}:</strong> {tech_name}</p>"
        
        # Format vulnerabilities
        vulnerabilities_html = ""
        for vuln in report_data['vulnerabilities']:
            vuln_class = vuln['severity'].lower()
            vulnerabilities_html += f"""
            <div class="vulnerability {vuln_class}">
                <h3>🔴 {vuln['type']} ({vuln['severity']})</h3>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>URL:</strong> {vuln['url']}</p>
                {f"<p><strong>Evidence:</strong> {vuln['evidence']}</p>" if 'evidence' in vuln else ""}
            </div>
            """
        
        html_content = html_template.format(
            target=report_data['target'],
            scan_date=report_data['scan_timestamp'],
            total_vulns=report_data['summary']['total_vulnerabilities'],
            high_count=report_data['summary']['severity_breakdown']['High'],
            medium_count=report_data['summary']['severity_breakdown']['Medium'],
            low_count=report_data['summary']['severity_breakdown']['Low'],
            tech_stack=tech_stack,
            vulnerabilities=vulnerabilities_html
        )
        
        # Save HTML report
        report_path = os.path.join(self.logger.output_dir, f"vulnerability_report_{self.logger.timestamp}.html")
        with open(report_path, 'w') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] HTML report saved to: {report_path}")

# =================================================================
# NETWORK RECONNAISSANCE
# =================================================================
class NetworkRecon:
    def __init__(self, target):
        self.target = target
        self.logger = Logger()
        self.api_client = APIClient()
    
    def whois_lookup(self):
        print(f"\n{Fore.CYAN}--- WHOIS Information ---")
        try:
            w = whois.whois(self.target)
            whois_data = {
                'domain': self.target,
                'registrar': str(w.registrar) if w.registrar else 'Unknown',
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'name_servers': w.name_servers if w.name_servers else [],
                'org': str(w.org) if w.org else 'Unknown',
                'country': str(w.country) if w.country else 'Unknown',
                'emails': w.emails if w.emails else []
            }
            
            print(f"{Fore.GREEN}[+] Registrar: {whois_data['registrar']}")
            print(f"{Fore.GREEN}[+] Creation Date: {whois_data['creation_date']}")
            print(f"{Fore.GREEN}[+] Expiration Date: {whois_data['expiration_date']}")
            print(f"{Fore.GREEN}[+] Organization: {whois_data['org']}")
            print(f"{Fore.GREEN}[+] Country: {whois_data['country']}")
            
            if whois_data['name_servers']:
                print(f"{Fore.GREEN}[+] Name Servers:")
                for ns in whois_data['name_servers']:
                    print(f"    - {ns}")
            
            if whois_data['emails']:
                print(f"{Fore.GREEN}[+] Contact Emails:")
                for email in whois_data['emails']:
                    print(f"    - {email}")
            
            return whois_data
        except Exception as e:
            print(f"{Fore.RED}[!] WHOIS lookup failed: {e}")
            return {}
    
    def dns_enumeration(self):
        print(f"\n{Fore.CYAN}--- DNS Enumeration ---")
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                dns_records[record_type] = records
                print(f"{Fore.GREEN}[+] {record_type} Records:")
                for record in records:
                    print(f"    - {record}")
            except dns.resolver.NXDOMAIN:
                print(f"{Fore.RED}[!] Domain {self.target} does not exist")
                break
            except dns.resolver.NoAnswer:
                dns_records[record_type] = []
            except Exception as e:
                print(f"{Fore.RED}[!] Error querying {record_type}: {e}")
                dns_records[record_type] = []
        
        return dns_records
    
    def shodan_recon(self):
        print(f"\n{Fore.CYAN}--- Shodan Intelligence ---")
        if not CONFIG['SHODAN_API_KEY']:
            print(f"{Fore.YELLOW}[!] Shodan API key not configured")
            return []
        
        try:
            # Get IP address first
            ip = socket.gethostbyname(self.target)
            print(f"{Fore.GREEN}[+] Target IP: {ip}")
            
            # Search Shodan
            results = self.api_client.shodan_search(f'hostname:{self.target}')
            
            shodan_data = []
            for result in results[:10]:  # Limit results
                data = {
                    'ip': result.get('ip_str'),
                    'port': result.get('port'),
                    'service': result.get('product', 'Unknown'),
                    'version': result.get('version', 'Unknown'),
                    'org': result.get('org', 'Unknown'),
                    'country': result.get('location', {}).get('country_name', 'Unknown'),
                    'city': result.get('location', {}).get('city', 'Unknown'),
                    'banner': result.get('data', '')[:200] + '...' if len(result.get('data', '')) > 200 else result.get('data', '')
                }
                shodan_data.append(data)
                
                print(f"{Fore.GREEN}[+] {data['ip']}:{data['port']} - {data['service']} {data['version']}")
                print(f"    Org: {data['org']}")
                print(f"    Location: {data['city']}, {data['country']}")
            
            return shodan_data
        except Exception as e:
            print(f"{Fore.RED}[!] Shodan search failed: {e}")
            return []
    
    def run_full_recon(self):
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} NETWORK RECONNAISSANCE FOR: {self.target} {'='*20}")
        
        recon_data = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'whois': self.whois_lookup(),
            'dns_records': self.dns_enumeration(),
            'shodan_intel': self.shodan_recon()
        }
        
        # Save results
        self.logger.save_json(recon_data, "network_recon")
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} NETWORK RECONNAISSANCE COMPLETE {'='*38}")
        return recon_data

# =================================================================
# EMAIL HARVESTING
# =================================================================
class EmailHarvester:
    def __init__(self, domain):
        self.domain = domain
        self.found_emails = set()
        self.logger = Logger()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(CONFIG['USER_AGENTS'])
        })
    
    def _extract_emails_from_text(self, text):
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = email_pattern.findall(text)
        domain_emails = [email for email in emails if self.domain in email.lower()]
        return domain_emails
    
    def google_dorking(self):
        print(f"{Fore.BLUE}[*] Searching emails via Google dorking...")
        queries = [
            f'"{self.domain}" email',
            f'site:{self.domain} "@{self.domain}"',
            f'"@{self.domain}" contact',
            f'"{self.domain}" "contact us"',
        ]
        
        for query in queries:
            try:
                url = f"https://www.google.com/search?q={quote(query)}&num=50"
                resp = self.session.get(url, timeout=10)
                emails = self._extract_emails_from_text(resp.text)
                
                for email in emails:
                    self.found_emails.add(email)
                    print(f"{Fore.GREEN}[+] Email found: {email}")
                
                time.sleep(random.uniform(2, 5))  # Rate limiting
            except Exception as e:
                print(f"{Fore.RED}[!] Google search error: {e}")
    
    def hunter_io_search(self):
        print(f"{Fore.BLUE}[*] Searching Hunter.io...")
        emails = self.api_client.hunter_io_emails(self.domain)
        for email in emails:
            self.found_emails.add(email)
            print(f"{Fore.GREEN}[+] Hunter.io: {email}")
            
    def _free_email_sources(self):
        """Free email discovery sources"""
        print(f"{Fore.BLUE}[*] Searching free email sources...")
        
        # Phonebook.cz
        try:
            url = f"https://phonebook.cz/search?q={self.domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                emails = self._extract_emails_from_text(resp.text)
                for email in emails:
                    self.found_emails.add(email)
                    print(f"{Fore.GREEN}[+] Phonebook: {email}")
        except Exception as e:
            print(f"{Fore.RED}[!] Phonebook.cz error: {e}")
            
        # IntelligenceX (limited free tier)
        try:
            url = f"https://2.intelx.io/phonebook/search?term={self.domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get('records', []):
                    email = record.get('name', '')
                    if '@' in email and self.domain in email.lower():
                        self.found_emails.add(email)
                        print(f"{Fore.GREEN}[+] IntelX: {email}")
        except Exception:
            pass
    
    def github_search(self):
        print(f"{Fore.BLUE}[*] Searching GitHub...")
        try:
            url = f"https://api.github.com/search/code?q={self.domain}+in:file"
            resp = self.session.get(url, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('items', [])[:10]:  # Limit results
                    # Download file content
                    content_url = item.get('url')
                    if content_url:
                        try:
                            content_resp = self.session.get(content_url, timeout=5)
                            if content_resp.status_code == 200:
                                content = base64.b64decode(content_resp.json().get('content', '')).decode('utf-8', errors='ignore')
                                emails = self._extract_emails_from_text(content)
                                for email in emails:
                                    self.found_emails.add(email)
                                    print(f"{Fore.GREEN}[+] GitHub: {email}")
                        except:
                            continue
        except Exception as e:
            print(f"{Fore.RED}[!] GitHub search error: {e}")
    
    def run_harvest(self):
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} EMAIL HARVESTING FOR: {self.domain} {'='*20}")
        
        self.google_dorking()
        self.hunter_io_search()
        self._free_email_sources()
        self.github_search()
        
        email_list = list(self.found_emails)
        print(f"\n{Fore.GREEN}[+] Total emails found: {len(email_list)}")
        
        if email_list:
            # Save results
            self.logger.save_json(email_list, "email_harvest")
            self.logger.save_txt(email_list, "emails")
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} EMAIL HARVESTING COMPLETE {'='*38}")
        return email_list

# =================================================================
# MAIN FUNCTION & CLI
# =================================================================
def create_wordlist_files():
    """Create default wordlist files if they don't exist"""
    
    # Create subdomains.txt
    if not os.path.exists('subdomains.txt'):
        with open('subdomains.txt', 'w') as f:
            f.write('\n'.join(SUBDOMAIN_WORDLIST))
        print(f"{Fore.GREEN}[+] Created subdomains.txt with {len(SUBDOMAIN_WORDLIST)} entries")
    
    # Create directories.txt
    if not os.path.exists('directories.txt'):
        with open('directories.txt', 'w') as f:
            f.write('\n'.join(DIRECTORY_WORDLIST))
        print(f"{Fore.GREEN}[+] Created directories.txt with {len(DIRECTORY_WORDLIST)} entries")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_banner()
    
    # Create default wordlists
    create_wordlist_files()
    
    parser = argparse.ArgumentParser(description="Sentinel v3 - Advanced OSINT & Reconnaissance Framework")
    subparsers = parser.add_subparsers(dest='mode', help='Operation modes')
    
    # Enhanced Recon Mode
    recon_parser = subparsers.add_parser('recon', help='Advanced subdomain discovery')
    recon_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    recon_parser.add_argument('-w', '--wordlist', default='subdomains.txt', help='Subdomain wordlist file')
    recon_parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    recon_parser.add_argument('--no-wordlist', action='store_true', help='Skip wordlist bruteforce')
    recon_parser.add_argument('--no-dns', action='store_true', help='Skip DNS enumeration')
    recon_parser.add_argument('--no-crt', action='store_true', help='Skip certificate transparency')
    recon_parser.add_argument('--no-api', action='store_true', help='Skip API-based discovery')
    
    # Enhanced Scan Mode
    scan_parser = subparsers.add_parser('scan', help='Advanced content discovery')
    scan_parser.add_argument('-u', '--url', required=True, help='Target URL')
    scan_parser.add_argument('-w', '--wordlist', default='directories.txt', help='Directory wordlist file')
    scan_parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    scan_parser.add_argument('--no-backups', action='store_true', help='Skip backup file discovery')
    scan_parser.add_argument('--status-codes', action='store_true', help='Show all HTTP status codes')
    
    # Enhanced Vuln Mode
    vuln_parser = subparsers.add_parser('vuln', help='Advanced vulnerability analysis')
    vuln_parser.add_argument('-u', '--url', help='Single target URL')
    vuln_parser.add_argument('-f', '--file', help='File with list of URLs')
    vuln_parser.add_argument('--quick', action='store_true', help='Quick scan (skip deep analysis)')
    
    # Network Recon Mode
    network_parser = subparsers.add_parser('network', help='Network reconnaissance')
    network_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    
    # Email Harvesting Mode
    email_parser = subparsers.add_parser('email', help='Email harvesting')
    email_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    
    # Full Scan Mode (All-in-one)
    full_parser = subparsers.add_parser('full', help='Complete reconnaissance suite')
    full_parser.add_argument('-d', '--domain', required=True, help='Target domain')
    full_parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads')
    
    # Configuration Mode
    config_parser = subparsers.add_parser('config', help='Configure API keys')
    config_parser.add_argument('--shodan', help='Set Shodan API key')
    config_parser.add_argument('--virustotal', help='Set VirusTotal API key')
    config_parser.add_argument('--hunter', help='Set Hunter.io API key')
    config_parser.add_argument('--securitytrails', help='Set SecurityTrails API key')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')
    
    args = parser.parse_args()
    
    if args.mode == 'recon':
        scanner = EnhancedSubdomainScanner(
            domain=args.domain,
            threads=args.threads,
            use_wordlist=not args.no_wordlist,
            use_dns=not args.no_dns,
            use_crt=not args.no_crt,
            use_api=not args.no_api
        )
        results = scanner.run()
        
    elif args.mode == 'scan':
        scanner = EnhancedContentScanner(
            base_url=args.url,
            threads=args.threads,
            check_status_codes=args.status_codes,
            find_backups=not args.no_backups
        )
        results = scanner.run()
        
    elif args.mode == 'vuln':
        if args.url:
            scanner = EnhancedVulnScanner(target_url=args.url)
            scanner.run_all_checks()
        elif args.file:
            if not os.path.exists(args.file):
                print(f"{Fore.RED}[!] File not found: {args.file}")
                return
            
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"{Fore.BLUE}[*] Scanning {len(urls)} URLs from file...")
            for i, url in enumerate(urls, 1):
                print(f"\n{Fore.CYAN}[*] Scanning {i}/{len(urls)}: {url}")
                scanner = EnhancedVulnScanner(target_url=url)
                if args.quick:
                    # Quick scan - only basic checks
                    scanner._check_security_headers()
                    scanner._check_subdomain_takeover()
                else:
                    scanner.run_all_checks()
        else:
            print(f"{Fore.RED}[!] Provide URL (-u) or file (-f) for vulnerability scanning")
            
    elif args.mode == 'network':
        recon = NetworkRecon(target=args.domain)
        results = recon.run_full_recon()
        
    elif args.mode == 'email':
        harvester = EmailHarvester(domain=args.domain)
        results = harvester.run_harvest()
        
    elif args.mode == 'full':
        print(f"{Fore.MAGENTA}{Style.BRIGHT}{'='*60}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}FULL RECONNAISSANCE SUITE FOR: {args.domain}")
        print(f"{Fore.MAGENTA}{Style.BRIGHT}{'='*60}")
        
        # 1. Network Reconnaissance
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 PHASE 1: NETWORK RECONNAISSANCE")
        network_recon = NetworkRecon(target=args.domain)
        network_results = network_recon.run_full_recon()
        
        # 2. Subdomain Discovery
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 PHASE 2: SUBDOMAIN DISCOVERY")
        subdomain_scanner = EnhancedSubdomainScanner(
            domain=args.domain,
            threads=args.threads
        )
        subdomains = subdomain_scanner.run()
        
        # 3. Email Harvesting
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 PHASE 3: EMAIL HARVESTING")
        email_harvester = EmailHarvester(domain=args.domain)
        emails = email_harvester.run_harvest()
        
        # 4. Content Discovery on main domain
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 PHASE 4: CONTENT DISCOVERY")
        main_url = f"https://{args.domain}"
        content_scanner = EnhancedContentScanner(
            base_url=main_url,
            threads=args.threads//2  # Use fewer threads for content scan
        )
        content_results = content_scanner.run()
        
        # 5. Vulnerability Assessment on discovered assets
        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 PHASE 5: VULNERABILITY ASSESSMENT")
        
        # Scan main domain
        vuln_scanner = EnhancedVulnScanner(target_url=main_url)
        main_vulns = vuln_scanner.run_all_checks()
        
        # Scan top 5 subdomains
        if subdomains:
            print(f"\n{Fore.BLUE}[*] Scanning top 5 subdomains for vulnerabilities...")
            for subdomain_data in subdomains[:5]:
                subdomain_url = f"https://{subdomain_data['subdomain']}"
                print(f"\n{Fore.CYAN}[*] Scanning: {subdomain_url}")
                try:
                    vuln_scanner = EnhancedVulnScanner(target_url=subdomain_url)
                    vuln_scanner.run_all_checks()
                except Exception as e:
                    print(f"{Fore.RED}[!] Error scanning {subdomain_url}: {e}")
        
        # Generate comprehensive report
        comprehensive_report = {
            'target': args.domain,
            'scan_timestamp': datetime.now().isoformat(),
            'network_intelligence': network_results,
            'subdomains_discovered': len(subdomains),
            'subdomain_details': subdomains,
            'emails_found': len(emails),
            'email_addresses': emails,
            'content_paths': len(content_results),
            'content_details': content_results,
            'vulnerability_summary': {
                'total_scanned': len(subdomains) + 1,
                'main_domain_vulns': len(main_vulns)
            }
        }
        
        logger = Logger()
        logger.save_json(comprehensive_report, "comprehensive_report")
        
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'='*20} FULL RECONNAISSANCE COMPLETE {'='*20}")
        print(f"{Fore.GREEN}[+] Subdomains discovered: {len(subdomains)}")
        print(f"{Fore.GREEN}[+] Emails found: {len(emails)}")
        print(f"{Fore.GREEN}[+] Content paths: {len(content_results)}")
        print(f"{Fore.GREEN}[+] Comprehensive report saved")
        
    elif args.mode == 'config':
        config_file = 'sentinel_config.json'
        
        if args.show:
            # Show current configuration
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    print(f"{Fore.CYAN}Current Configuration:")
                    for key, value in config.items():
                        if value:
                            masked_value = value[:8] + "..." if len(value) > 8 else value
                            print(f"  {key}: {masked_value}")
                        else:
                            print(f"  {key}: Not set")
            else:
                print(f"{Fore.YELLOW}[!] No configuration file found")
            return
        
        # Load existing config
        config = CONFIG.copy()
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config.update(json.load(f))
        
        # Update configuration
        if args.shodan:
            config['SHODAN_API_KEY'] = args.shodan
            print(f"{Fore.GREEN}[+] Shodan API key updated")
            
        if args.virustotal:
            config['VIRUSTOTAL_API_KEY'] = args.virustotal
            print(f"{Fore.GREEN}[+] VirusTotal API key updated")
            
        if args.hunter:
            config['HUNTER_API_KEY'] = args.hunter
            print(f"{Fore.GREEN}[+] Hunter.io API key updated")
            
        if args.securitytrails:
            config['SECURITYTRAILS_API_KEY'] = args.securitytrails
            print(f"{Fore.GREEN}[+] SecurityTrails API key updated")
        
        # Save configuration
        with open(config_file, 'w') as f:
            json.dump({k: v for k, v in config.items() if k.endswith('_KEY') or k.endswith('_ID') or k.endswith('_SECRET')}, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Configuration saved to {config_file}")
        
        # Update global config
        CONFIG.update(config)
        
    else:
        parser.print_help()
        print(f"\n{Fore.CYAN}Examples:")
        print(f"  {Fore.YELLOW}python sentinel.py recon -d example.com")
        print(f"  {Fore.YELLOW}python sentinel.py scan -u https://example.com")
        print(f"  {Fore.YELLOW}python sentinel.py vuln -u https://example.com")
        print(f"  {Fore.YELLOW}python sentinel.py network -d example.com")
        print(f"  {Fore.YELLOW}python sentinel.py email -d example.com")
        print(f"  {Fore.YELLOW}python sentinel.py full -d example.com")
        print(f"  {Fore.YELLOW}python sentinel.py config --shodan YOUR_API_KEY --hunter YOUR_HUNTER_KEY")
        print(f"\n{Fore.GREEN}Free APIs Available:")
        print(f"  {Fore.WHITE}• RapidDNS - Free subdomain discovery")
        print(f"  {Fore.WHITE}• AlienVault OTX - Free threat intelligence")
        print(f"  {Fore.WHITE}• ThreatCrowd - Free subdomain data") 
        print(f"  {Fore.WHITE}• HackerTarget - Free reconnaissance")
        print(f"  {Fore.WHITE}• Certificate Transparency logs")
        print(f"  {Fore.WHITE}• Wayback Machine archives")
        print(f"\n{Fore.CYAN}Premium APIs (Optional):")
        print(f"  {Fore.WHITE}• Shodan - Network intelligence")
        print(f"  {Fore.WHITE}• VirusTotal - Threat analysis") 
        print(f"  {Fore.WHITE}• Hunter.io - Email discovery")
        print(f"  {Fore.WHITE}• SecurityTrails - DNS history")
        print(f"\n{Fore.GREEN}Features:")
        print(f"  {Fore.WHITE}• Enhanced subdomain discovery with multiple sources")
        print(f"  {Fore.WHITE}• Advanced content discovery with backup file detection")
        print(f"  {Fore.WHITE}• Comprehensive vulnerability assessment")
        print(f"  {Fore.WHITE}• Network reconnaissance with WHOIS and DNS")
        print(f"  {Fore.WHITE}• Email harvesting from multiple sources")
        print(f"  {Fore.WHITE}• API integration (Shodan, VirusTotal, etc.)")
        print(f"  {Fore.WHITE}• Automated report generation (JSON, CSV, HTML)")
        print(f"  {Fore.WHITE}• Built-in wordlists and signatures")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Unexpected error: {e}")
        sys.exit(1)
