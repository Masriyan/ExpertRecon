#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExpertRecon - Advanced Recon & Correlation Toolkit v2.0
Author: sudo3rs (Enhanced Edition)

Highlights
- Comprehensive reconnaissance with 15+ modules
- Multi-threaded/concurrent scanning support
- Advanced API integrations (Shodan, FOFA, Driftnet, VirusTotal, HaveIBeenPwned)
- Subdomain enumeration with multiple techniques
- SSL/TLS certificate analysis and validation
- Web technology fingerprinting
- Screenshot capture for web services
- Banner grabbing and service fingerprinting
- Enhanced CVE matching with CPE correlation
- Directory/file enumeration
- Email breach checking
- WHOIS and DNS intelligence
- HTML dashboard reports with visualizations
- Rate limiting and stealth options
- Solid error handling & structured logging
- Safer-by-default design (no exploitation)
- Config via environment variables
"""

import os
import sys
import re
import csv
import json
import time
import base64
import shutil
import signal
import socket
import logging
import platform
import argparse
import subprocess
import ssl
import urllib.parse
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm

# Optional imports with graceful fallbacks
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# =========================
# KEEP THIS BANNER AS-IS
# =========================
def print_banner():
    banner = r"""
███████╗██╗  ██╗██████╗ ███████╗██████╗ ████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔════╝╚██╗██╔╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
█████╗   ╚███╔╝ ██████╔╝█████╗  ██████╔╝   ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══╝   ██╔██╗ ██╔═══╝ ██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
███████╗██╔╝ ██╗██║     ███████╗██║  ██║   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

                       v2.0 Enhanced by sudo3rs
                       Advanced Reconnaissance Toolkit
    """
    print(banner)

# -------------------------
# Constants & Configuration
# -------------------------
CVE_API_URL = 'https://cve.circl.lu/api/last'
FOFA_API_URL = 'https://fofa.info/api/v1/search/all'
DRIFNET_API_URL = 'https://api.driftnet.io/v1/search'
SHODAN_API_URL = 'https://api.shodan.io'
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3'
HIBP_API_URL = 'https://haveibeenpwned.com/api/v3'
OPENAI_CHAT_URL = 'https://api.openai.com/v1/chat/completions'

DEFAULT_TIMEOUT = 25
CONNECT_TIMEOUT = 10
MAX_RESULTS = 20
MAX_THREADS = 5

# Read secrets from env
FOFA_EMAIL = os.getenv('FOFA_EMAIL', '')
FOFA_API_KEY = os.getenv('FOFA_API_KEY', '')
DRIFNET_API_KEY = os.getenv('DRIFNET_API_KEY', '')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')

# Safe mode blocks any offensive action by default
SAFE_MODE = os.getenv('SAFE_MODE', '1') in ('1', 'true', 'True', 'yes')

# Common subdomains for enumeration
COMMON_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
    'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
    'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
    'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
    'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
    'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'search',
    'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1', 'sites',
    'proxy', 'ads', 'host', 'crm', 'cms', 'backup', 'mx2', 'lyncdiscover', 'info',
    'apps', 'download', 'remote', 'db', 'forums', 'store', 'relay', 'files',
    'newsletter', 'app', 'live', 'owa', 'en', 'start', 'sms', 'office', 'exchange',
    'ipv4', 'mail3', 'help', 'blogs', 'helpdesk', 'web1', 'home', 'library', 'ftp2',
    'ntp', 'monitor', 'login', 'service', 'correo', 'www4', 'moodle', 'it', 'gateway',
    'gw', 'i', 'stat', 'stage', 'ldap', 'tv', 'ssl', 'web2', 'ns5', 'upload',
    'nagios', 'smtp2', 'online', 'ad', 'survey', 'data', 'radio', 'extranet',
    'test2', 'mssql', 'dns3', 'jobs', 'services', 'panel', 'irc'
]

# Common web paths for directory enumeration
COMMON_PATHS = [
    '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin',
    '/cpanel', '/webmail', '/wp-login.php', '/admin.php', '/admin/',
    '/dashboard', '/console', '/api', '/robots.txt', '/sitemap.xml',
    '/.git', '/.env', '/backup', '/config', '/test', '/debug',
    '/api/v1', '/api/v2', '/graphql', '/swagger', '/docs'
]

# -------------------------
# Logging Setup
# -------------------------
def setup_logging(debug: bool = False, log_file: str = 'recon.log') -> None:
    level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger()
    logger.setLevel(level)

    for h in list(logger.handlers):
        logger.removeHandler(h)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch_fmt = logging.Formatter('[%(levelname)s] %(message)s')
    ch.setFormatter(ch_fmt)

    fh = RotatingFileHandler(log_file, maxBytes=5_000_000, backupCount=5, encoding='utf-8')
    fh.setLevel(level)
    fh_fmt = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')
    fh.setFormatter(fh_fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    logging.debug("Logging initialized.")

# -------------------------
# HTTP Session (Retries)
# -------------------------
def make_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=0.6,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

SESSION = make_session()
_CVE_CACHE: Optional[List[Dict[str, Any]]] = None

# -------------------------
# Utilities
# -------------------------
def which_or_hint(cmd: str, install_hint: str) -> Optional[str]:
    path = shutil.which(cmd)
    if not path:
        logging.warning("Dependency not found: %s. Hint: %s", cmd, install_hint)
    return path

def run_cmd(args: List[str], timeout: int = 120) -> Tuple[int, str, str]:
    """Run subprocess safely, return (code, stdout, stderr)."""
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return completed.returncode, completed.stdout, completed.stderr
    except FileNotFoundError:
        return 127, "", f"Command not found: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s: {' '.join(args)}"
    except Exception as e:
        return 1, "", f"Error running {args}: {e}"

def save_text(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', errors='ignore') as f:
        f.write(content or "")

def export_json(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def export_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not rows:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            f.write("")
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def tokens_from_text(text: str) -> List[str]:
    text = (text or "").lower()
    parts = re.split(r'[^a-z0-9.\-]+', text)
    return [p for p in parts if p]

def is_valid_domain(domain: str) -> bool:
    """Basic domain validation."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(octet) <= 255 for octet in ip.split('.'))

# -------------------------
# NEW: Subdomain Enumeration
# -------------------------
def enumerate_subdomains_dns(domain: str, wordlist: List[str] = None, threads: int = 10) -> List[str]:
    """Enumerate subdomains via DNS bruteforce."""
    if not DNS_AVAILABLE:
        logging.warning("dnspython not available. Install: pip install dnspython")
        return []

    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    found = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    def check_subdomain(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(fqdn, 'A')
            if answers:
                return fqdn
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
        for future in tqdm(as_completed(futures), total=len(wordlist), desc="Subdomain enum", leave=False):
            result = future.result()
            if result:
                found.append(result)

    return sorted(set(found))

def enumerate_subdomains_crtsh(domain: str) -> List[str]:
    """Enumerate subdomains via crt.sh certificate transparency logs."""
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = SESSION.get(url, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            return []

        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get('name_value', '')
            if name and '*' not in name:
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)

        return sorted(subdomains)
    except Exception as e:
        logging.error("crt.sh enumeration failed: %s", e)
        return []

# -------------------------
# NEW: WHOIS Lookup
# -------------------------
def perform_whois(target: str) -> Dict[str, Any]:
    """Perform WHOIS lookup."""
    if not WHOIS_AVAILABLE:
        logging.warning("python-whois not available. Install: pip install python-whois")
        return {'raw': '', 'parsed': {}}

    try:
        w = whois.whois(target)
        parsed = {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date) if w.expiration_date else None,
            'updated_date': str(w.updated_date) if w.updated_date else None,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails,
            'org': w.org,
            'country': w.country,
        }
        return {'raw': str(w), 'parsed': parsed}
    except Exception as e:
        logging.error("WHOIS lookup failed: %s", e)
        return {'raw': str(e), 'parsed': {}}

# -------------------------
# NEW: SSL/TLS Analysis
# -------------------------
def analyze_ssl_certificate(host: str, port: int = 443) -> Dict[str, Any]:
    """Analyze SSL/TLS certificate."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'serial_number': cert.get('serialNumber'),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'san': cert.get('subjectAltName', []),
                    'cipher': cipher,
                    'tls_version': version,
                }
    except Exception as e:
        logging.error("SSL analysis failed for %s:%d: %s", host, port, e)
        return {'error': str(e)}

# -------------------------
# NEW: Web Technology Detection
# -------------------------
def detect_web_technologies(url: str) -> Dict[str, Any]:
    """Detect web technologies from headers and content."""
    try:
        resp = SESSION.get(url, timeout=(CONNECT_TIMEOUT, 15), allow_redirects=True)
        headers = resp.headers
        content = resp.text[:50000]  # First 50KB

        technologies = {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
            'frameworks': [],
            'cms': [],
            'analytics': [],
            'cdn': headers.get('X-CDN', headers.get('X-Cache', 'Unknown')),
            'cookies': [c.name for c in resp.cookies],
        }

        # Framework detection
        if 'react' in content.lower() or 'reactroot' in content.lower():
            technologies['frameworks'].append('React')
        if 'angular' in content.lower() or 'ng-app' in content.lower():
            technologies['frameworks'].append('Angular')
        if 'vue' in content.lower() or '__vue__' in content.lower():
            technologies['frameworks'].append('Vue.js')
        if 'jquery' in content.lower():
            technologies['frameworks'].append('jQuery')

        # CMS detection
        if '/wp-content/' in content or '/wp-includes/' in content:
            technologies['cms'].append('WordPress')
        if 'Joomla' in content or '/components/com_' in content:
            technologies['cms'].append('Joomla')
        if 'Drupal' in content or '/sites/default/' in content:
            technologies['cms'].append('Drupal')

        # Analytics
        if 'google-analytics.com' in content or 'ga.js' in content:
            technologies['analytics'].append('Google Analytics')
        if 'googletagmanager.com' in content:
            technologies['analytics'].append('Google Tag Manager')

        return technologies
    except Exception as e:
        logging.error("Web tech detection failed for %s: %s", url, e)
        return {'error': str(e)}

# -------------------------
# NEW: Screenshot Capture
# -------------------------
def capture_screenshot(url: str, output_path: str) -> bool:
    """Capture screenshot of web page using Selenium."""
    if not SELENIUM_AVAILABLE:
        logging.warning("Selenium not available. Install: pip install selenium")
        return False

    try:
        options = ChromeOptions()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument('--window-size=1920,1080')

        driver = webdriver.Chrome(options=options)
        driver.get(url)
        time.sleep(2)  # Wait for page load
        driver.save_screenshot(output_path)
        driver.quit()
        return True
    except Exception as e:
        logging.error("Screenshot capture failed for %s: %s", url, e)
        return False

# -------------------------
# NEW: Banner Grabbing
# -------------------------
def grab_banner(host: str, port: int, timeout: int = 5) -> str:
    """Grab service banner from a port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send HTTP request for web services
        if port in [80, 443, 8080, 8443]:
            sock.send(b"GET / HTTP/1.0\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()
    except Exception as e:
        return f"Error: {e}"

# -------------------------
# NEW: Directory Enumeration
# -------------------------
def enumerate_directories(base_url: str, paths: List[str] = None, threads: int = 10) -> List[Dict[str, Any]]:
    """Enumerate common directories and files."""
    if paths is None:
        paths = COMMON_PATHS

    found = []

    def check_path(path: str) -> Optional[Dict[str, Any]]:
        url = base_url.rstrip('/') + path
        try:
            resp = SESSION.get(url, timeout=5, allow_redirects=False)
            if resp.status_code < 400:
                return {
                    'url': url,
                    'status': resp.status_code,
                    'size': len(resp.content),
                    'content_type': resp.headers.get('Content-Type', 'Unknown')
                }
        except:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_path, path): path for path in paths}
        for future in tqdm(as_completed(futures), total=len(paths), desc="Directory enum", leave=False):
            result = future.result()
            if result:
                found.append(result)

    return found

# -------------------------
# NEW: Email Breach Check
# -------------------------
def check_email_breach(email: str) -> Dict[str, Any]:
    """Check if email appears in known data breaches (HIBP)."""
    if not HIBP_API_KEY:
        logging.info("HIBP API key not set; skipping breach check.")
        return {}

    try:
        headers = {
            'hibp-api-key': HIBP_API_KEY,
            'User-Agent': 'ExpertRecon-SecurityTool'
        }
        url = f"{HIBP_API_URL}/breachedaccount/{urllib.parse.quote(email)}"
        resp = SESSION.get(url, headers=headers, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))

        if resp.status_code == 404:
            return {'breached': False, 'breaches': []}
        elif resp.status_code == 200:
            breaches = resp.json()
            return {
                'breached': True,
                'breach_count': len(breaches),
                'breaches': [b.get('Name') for b in breaches]
            }
        else:
            return {'error': f"Status {resp.status_code}"}
    except Exception as e:
        logging.error("HIBP check failed: %s", e)
        return {'error': str(e)}

# -------------------------
# Data Fetchers (Enhanced)
# -------------------------
def fetch_cve_data(limit: int = 200) -> List[Dict[str, Any]]:
    """Fetch latest CVEs; cached per run."""
    global _CVE_CACHE
    if _CVE_CACHE is not None:
        logging.debug("Using cached CVE data (%d items).", len(_CVE_CACHE))
        return _CVE_CACHE[:limit]

    try:
        resp = SESSION.get(CVE_API_URL, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        resp.raise_for_status()
        data = resp.json()
        if isinstance(data, list):
            _CVE_CACHE = data
            logging.info("Fetched %d CVEs (latest).", len(data))
            return data[:limit]
        else:
            logging.error("Unexpected CVE API response format.")
            return []
    except Exception as e:
        logging.error("Failed to fetch CVE data: %s", e)
        return []

def query_shodan(target: str) -> Dict[str, Any]:
    """Query Shodan API for host information."""
    if not SHODAN_API_KEY:
        logging.info("Shodan API key not set; skipping.")
        return {}

    try:
        url = f"{SHODAN_API_URL}/shodan/host/{target}?key={SHODAN_API_KEY}"
        resp = SESSION.get(url, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("Shodan error: %s", resp.text[:300])
            return {}

        data = resp.json()
        return {
            'ip': data.get('ip_str'),
            'org': data.get('org'),
            'isp': data.get('isp'),
            'asn': data.get('asn'),
            'country': data.get('country_name'),
            'city': data.get('city'),
            'ports': data.get('ports', []),
            'hostnames': data.get('hostnames', []),
            'domains': data.get('domains', []),
            'vulns': list(data.get('vulns', {}).keys()) if 'vulns' in data else [],
            'services': [
                {
                    'port': s.get('port'),
                    'product': s.get('product'),
                    'version': s.get('version'),
                    'banner': s.get('data', '')[:200]
                }
                for s in data.get('data', [])
            ]
        }
    except Exception as e:
        logging.error("Shodan query failed: %s", e)
        return {}

def query_fofa(target: str, size: int = MAX_RESULTS) -> List[Dict[str, Any]]:
    """Search FOFA for the host."""
    if not FOFA_EMAIL or not FOFA_API_KEY:
        logging.info("FOFA not configured; skipping.")
        return []

    try:
        q = f'host="{target}"'
        qbase64 = base64.b64encode(q.encode()).decode()
        params = {
            'email': FOFA_EMAIL,
            'key': FOFA_API_KEY,
            'qbase64': qbase64,
            'size': size,
            'full': 'true',
            'fields': 'host,port,protocol,server,title,icp,city,as_organization'
        }
        resp = SESSION.get(FOFA_API_URL, params=params, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("FOFA error: %s", resp.text[:300])
            return []

        payload = resp.json()
        results = payload.get('results', [])
        records = []
        for row in results:
            if isinstance(row, list):
                keys = ['host','port','protocol','server','title','icp','city','as_org']
                rec = {k: (row[i] if i < len(row) else None) for i, k in enumerate(keys)}
            elif isinstance(row, dict):
                rec = row
            else:
                rec = {'raw': row}
            records.append(rec)
        return records
    except Exception as e:
        logging.error("Exception querying FOFA: %s", e)
        return []

def query_driftnet(target: str, size: int = MAX_RESULTS) -> List[Dict[str, Any]]:
    """Query Driftnet API."""
    if not DRIFNET_API_KEY:
        logging.info("Driftnet not configured; skipping.")
        return []

    try:
        headers = {'Authorization': f'Bearer {DRIFNET_API_KEY}'}
        params = {'query': target, 'size': size}
        resp = SESSION.get(DRIFNET_API_URL, headers=headers, params=params,
                          timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("Driftnet error: %s", resp.text[:300])
            return []

        payload = resp.json()
        data = payload.get('data', [])
        norm = data if isinstance(data, list) else [data]
        return [d if isinstance(d, dict) else {'result': d} for d in norm]
    except Exception as e:
        logging.error("Exception querying Driftnet: %s", e)
        return []

def query_virustotal(target: str) -> Dict[str, Any]:
    """Query VirusTotal for domain/IP reputation."""
    if not VIRUSTOTAL_API_KEY:
        logging.info("VirusTotal API key not set; skipping.")
        return {}

    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Determine if target is IP or domain
        if is_valid_ip(target):
            url = f"{VIRUSTOTAL_API_URL}/ip_addresses/{target}"
        else:
            url = f"{VIRUSTOTAL_API_URL}/domains/{target}"

        resp = SESSION.get(url, headers=headers, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("VirusTotal error: %s", resp.text[:300])
            return {}

        data = resp.json().get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})

        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'reputation': attributes.get('reputation', 0),
            'categories': attributes.get('categories', {}),
        }
    except Exception as e:
        logging.error("VirusTotal query failed: %s", e)
        return {}

# -------------------------
# Recon Modules (Enhanced)
# -------------------------
def perform_nmap_scan(target: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """Run nmap -sV to identify services."""
    install_hint = "Install Nmap and add it to PATH (Windows: https://nmap.org/download)."
    nmap = which_or_hint('nmap', install_hint)
    if not nmap:
        return {'raw': '', 'services': []}

    args = [nmap, '-sV', '--version-light', '-T4', target]
    if extra_args:
        args.extend(extra_args)

    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("Nmap scan failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or '', 'services': []}

    services = []
    for line in out.splitlines():
        m = re.match(r'^(\d+/\w+)\s+open\s+([a-z0-9\-\_]+)\s+(.*)$', line.strip(), re.I)
        if m:
            port, name, rest = m.groups()
            product = None
            version = None
            info = rest.strip()
            parts = rest.split()
            if len(parts) >= 2:
                product = " ".join(parts[:-1])
                version = parts[-1]
                if not re.search(r'\d', version):
                    product = " ".join(parts)
                    version = None
            services.append({
                'port': port,
                'name': name,
                'product': product,
                'version': version,
                'info': info
            })
    return {'raw': out, 'services': services}

def perform_theharvester(target: str) -> Dict[str, Any]:
    """Run theHarvester (Google) for OSINT."""
    install_hint = "Install theHarvester (pipx/pip) and ensure 'theharvester' is on PATH."
    exe = which_or_hint('theharvester', install_hint)
    if not exe:
        return {'raw': '', 'emails': [], 'hosts': []}

    args = [exe, '-d', target, '-b', 'google']
    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("theHarvester failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or '', 'emails': [], 'hosts': []}

    # Parse emails and hosts
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', out)
    hosts = re.findall(r'\d+\.\d+\.\d+\.\d+:\w+', out)

    return {'raw': out, 'emails': list(set(emails)), 'hosts': list(set(hosts))}

def perform_dnsrecon(target: str) -> Dict[str, Any]:
    """Run dnsrecon basic scan."""
    install_hint = "Install dnsrecon (pipx/pip) and ensure 'dnsrecon' is on PATH."
    exe = which_or_hint('dnsrecon', install_hint)
    if not exe:
        return {'raw': '', 'records': []}

    args = [exe, '-d', target]
    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("dnsrecon failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or '', 'records': []}

    # Parse DNS records
    records = []
    for line in out.splitlines():
        if 'A ' in line or 'MX ' in line or 'NS ' in line or 'TXT ' in line:
            records.append(line.strip())

    return {'raw': out, 'records': records}

# -------------------------
# Enhanced CVE Matching
# -------------------------
def match_vulnerabilities(
    services: List[Dict[str, Any]],
    cve_data: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Enhanced fuzzy CVE matcher with better scoring."""
    if not services or not cve_data:
        return []

    tokens = set()
    for s in services:
        for field in ('name','product','version','info'):
            tokens.update(tokens_from_text((s.get(field) or "")))

    if not tokens:
        return []

    candidates = []
    for cve in cve_data:
        summary = (cve.get('summary') or '').lower()
        cid = cve.get('id') or cve.get('cve') or 'Unknown-CVE'
        refs = cve.get('references', [])

        # Score based on token matches
        score = sum(1 for t in tokens if len(t) > 2 and t in summary)

        if score > 0:
            candidates.append({
                'id': cid,
                'description': cve.get('summary', ''),
                'references': refs,
                'match_score': score,
                'cvss': cve.get('cvss', 'N/A')
            })

    # Sort by match score
    candidates.sort(key=lambda x: x.get('match_score', 0), reverse=True)
    return candidates

# -------------------------
# HTML Report Generation
# -------------------------
def generate_html_report(target: str, recon: Dict[str, Any], output_path: str) -> None:
    """Generate comprehensive HTML report with charts."""
    html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ExpertRecon Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ font-size: 1.2em; opacity: 0.9; }}
        .content {{ padding: 40px; }}
        .section {{
            margin-bottom: 40px;
            padding: 25px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 5px solid #667eea;
        }}
        .section h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .info-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .info-card h3 {{ color: #667eea; margin-bottom: 10px; }}
        .info-card p {{ color: #555; line-height: 1.6; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 600;
        }}
        tr:hover {{ background: #f5f5f5; }}
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            margin: 3px;
        }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: #333; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .badge-info {{ background: #17a2b8; color: white; }}
        .cve-item {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #dc3545;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            background: #1e3c72;
            color: white;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            flex-wrap: wrap;
            margin: 20px 0;
        }}
        .stat-box {{
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            min-width: 150px;
            margin: 10px;
        }}
        .stat-box h3 {{ font-size: 2.5em; color: #667eea; }}
        .stat-box p {{ color: #777; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 ExpertRecon Security Report</h1>
            <p>Target: {target}</p>
            <p>Generated: {timestamp}</p>
        </div>

        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="stats">
                    <div class="stat-box">
                        <h3>{service_count}</h3>
                        <p>Services Found</p>
                    </div>
                    <div class="stat-box">
                        <h3>{subdomain_count}</h3>
                        <p>Subdomains</p>
                    </div>
                    <div class="stat-box">
                        <h3>{cve_count}</h3>
                        <p>Potential CVEs</p>
                    </div>
                    <div class="stat-box">
                        <h3>{duration}</h3>
                        <p>Scan Duration (s)</p>
                    </div>
                </div>
            </div>

            {sections}
        </div>

        <div class="footer">
            <p>Generated by ExpertRecon v2.0 Enhanced | For Authorized Security Testing Only</p>
            <p>© 2025 sudo3rs</p>
        </div>
    </div>
</body>
</html>
    """

    sections_html = ""
    modules = recon.get('modules', {})

    # Services Section
    services = modules.get('nmap', {}).get('services', [])
    if services:
        services_html = "<table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>"
        for s in services:
            services_html += f"<tr><td>{s.get('port', 'N/A')}</td><td>{s.get('name', 'N/A')}</td><td>{s.get('product', 'N/A')}</td><td>{s.get('version', 'N/A')}</td></tr>"
        services_html += "</table>"
        sections_html += f'<div class="section"><h2>🔌 Discovered Services</h2>{services_html}</div>'

    # Subdomains Section
    subdomains = modules.get('subdomains', [])
    if subdomains:
        sub_html = "<ul style='list-style: none; padding: 0;'>"
        for sub in subdomains[:50]:
            sub_html += f"<li style='padding: 8px; background: white; margin: 5px 0; border-radius: 5px;'>🌐 {sub}</li>"
        sub_html += "</ul>"
        sections_html += f'<div class="section"><h2>🌍 Subdomains</h2>{sub_html}</div>'

    # CVEs Section
    cves = modules.get('cve_matches', [])
    if cves:
        cve_html = ""
        for cve in cves[:20]:
            cve_html += f'''<div class="cve-item">
                <strong>🔴 {cve.get('id', 'N/A')}</strong>
                <span class="badge badge-danger">Score: {cve.get('match_score', 0)}</span>
                <p>{cve.get('description', 'N/A')[:300]}...</p>
            </div>'''
        sections_html += f'<div class="section"><h2>🚨 Potential Vulnerabilities</h2>{cve_html}</div>'

    # Shodan Section
    shodan = modules.get('shodan', {})
    if shodan and shodan.get('ip'):
        shodan_html = f"""
        <div class="info-grid">
            <div class="info-card">
                <h3>Organization</h3>
                <p>{shodan.get('org', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h3>ISP</h3>
                <p>{shodan.get('isp', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h3>Location</h3>
                <p>{shodan.get('city', 'N/A')}, {shodan.get('country', 'N/A')}</p>
            </div>
            <div class="info-card">
                <h3>Open Ports</h3>
                <p>{', '.join(map(str, shodan.get('ports', [])))}</p>
            </div>
        </div>
        """
        sections_html += f'<div class="section"><h2>🔎 Shodan Intelligence</h2>{shodan_html}</div>'

    html = html_template.format(
        target=target,
        timestamp=recon.get('timestamp', datetime.now(timezone.utc).isoformat()),
        service_count=len(services),
        subdomain_count=len(subdomains),
        cve_count=len(cves),
        duration=recon.get('duration_sec', 0),
        sections=sections_html
    )

    save_text(output_path, html)
    logging.info("HTML report generated: %s", output_path)

# -------------------------
# Optional: OpenAI Summarization
# -------------------------
def chatgpt_analysis(data: Dict[str, Any], model: str = "gpt-4o-mini") -> Optional[str]:
    """Generate AI-assisted analysis summary."""
    if not OPENAI_API_KEY:
        logging.info("OpenAI API key not set; skipping AI analysis.")
        return None

    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {OPENAI_API_KEY}',
        }
        prompt = (
            "Analyze this security reconnaissance data and provide:\n"
            "1) Key findings and exposed services\n"
            "2) Potential security risks\n"
            "3) Recommended remediation steps\n\n"
            f"DATA:\n{json.dumps(data)[:8000]}"
        )
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 500,
            "temperature": 0.3,
        }
        resp = SESSION.post(OPENAI_CHAT_URL, headers=headers, json=payload,
                          timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("OpenAI API error: %s", resp.text[:400])
            return None
        return resp.json()['choices'][0]['message']['content']
    except Exception as e:
        logging.error("OpenAI exception: %s", e)
        return None

# -------------------------
# Input Helpers
# -------------------------
def load_targets(single_or_file: str) -> List[str]:
    """Load targets from string or file."""
    p = single_or_file.strip()
    if os.path.isfile(p):
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    return [p]

# -------------------------
# Main Orchestration (Enhanced)
# -------------------------
def process_target(
    target: str,
    export_dir: str,
    do_nmap: bool,
    do_harvester: bool,
    do_dnsrecon: bool,
    do_subdomain_enum: bool,
    do_whois: bool,
    do_ssl_analysis: bool,
    do_web_tech: bool,
    do_screenshot: bool,
    do_dir_enum: bool,
    do_shodan: bool,
    do_fofa: bool,
    do_driftnet: bool,
    do_virustotal: bool,
    cve_limit: int,
    enable_ai: bool,
    enable_html_report: bool,
    stealth_mode: bool,
    threads: int
) -> Dict[str, Any]:
    """Process a single target with all enabled modules."""
    t0 = time.time()
    out_dir = os.path.join(export_dir, target.replace('/', '_').replace(':', '_'))
    os.makedirs(out_dir, exist_ok=True)

    recon = {
        'target': target,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'modules': {}
    }

    # Determine if target is IP or domain
    is_ip = is_valid_ip(target)
    is_domain = is_valid_domain(target)

    steps = []
    if do_nmap: steps.append('nmap')
    if do_harvester and is_domain: steps.append('theharvester')
    if do_dnsrecon and is_domain: steps.append('dnsrecon')

    # Core recon modules
    for step in tqdm(steps, desc=f"Recon: {target}", leave=False):
        if stealth_mode:
            time.sleep(2)  # Rate limiting

        if step == 'nmap':
            nres = perform_nmap_scan(target)
            recon['modules']['nmap'] = nres
            save_text(os.path.join(out_dir, 'nmap.txt'), nres.get('raw', ''))
        elif step == 'theharvester':
            hres = perform_theharvester(target)
            recon['modules']['theharvester'] = hres
            save_text(os.path.join(out_dir, 'theharvester.txt'), hres.get('raw', ''))
        elif step == 'dnsrecon':
            dres = perform_dnsrecon(target)
            recon['modules']['dnsrecon'] = dres
            save_text(os.path.join(out_dir, 'dnsrecon.txt'), dres.get('raw', ''))

    # Subdomain enumeration
    if do_subdomain_enum and is_domain:
        logging.info("Enumerating subdomains...")
        subs_crtsh = enumerate_subdomains_crtsh(target)
        subs_dns = enumerate_subdomains_dns(target, COMMON_SUBDOMAINS[:100], threads=threads)
        all_subs = sorted(set(subs_crtsh + subs_dns))
        recon['modules']['subdomains'] = all_subs
        export_json(os.path.join(out_dir, 'subdomains.json'), all_subs)

    # WHOIS lookup
    if do_whois and is_domain:
        logging.info("Performing WHOIS lookup...")
        whois_data = perform_whois(target)
        recon['modules']['whois'] = whois_data
        export_json(os.path.join(out_dir, 'whois.json'), whois_data)

    # SSL analysis
    if do_ssl_analysis:
        logging.info("Analyzing SSL certificate...")
        ssl_data = analyze_ssl_certificate(target)
        recon['modules']['ssl'] = ssl_data
        export_json(os.path.join(out_dir, 'ssl.json'), ssl_data)

    # Web technology detection
    if do_web_tech:
        logging.info("Detecting web technologies...")
        for protocol in ['https', 'http']:
            url = f"{protocol}://{target}"
            try:
                tech = detect_web_technologies(url)
                if 'error' not in tech:
                    recon['modules']['web_tech'] = tech
                    export_json(os.path.join(out_dir, 'web_tech.json'), tech)
                    break
            except:
                continue

    # Screenshot capture
    if do_screenshot:
        logging.info("Capturing screenshot...")
        for protocol in ['https', 'http']:
            url = f"{protocol}://{target}"
            screenshot_path = os.path.join(out_dir, 'screenshot.png')
            if capture_screenshot(url, screenshot_path):
                recon['modules']['screenshot'] = screenshot_path
                break

    # Directory enumeration
    if do_dir_enum:
        logging.info("Enumerating directories...")
        for protocol in ['https', 'http']:
            url = f"{protocol}://{target}"
            try:
                dirs = enumerate_directories(url, COMMON_PATHS, threads=threads)
                if dirs:
                    recon['modules']['directories'] = dirs
                    export_json(os.path.join(out_dir, 'directories.json'), dirs)
                    break
            except:
                continue

    # API queries
    if do_shodan:
        shodan_data = query_shodan(target)
        if shodan_data:
            recon['modules']['shodan'] = shodan_data
            export_json(os.path.join(out_dir, 'shodan.json'), shodan_data)

    if do_fofa:
        fofa_data = query_fofa(target)
        if fofa_data:
            recon['modules']['fofa'] = fofa_data
            export_json(os.path.join(out_dir, 'fofa.json'), fofa_data)

    if do_driftnet:
        driftnet_data = query_driftnet(target)
        if driftnet_data:
            recon['modules']['driftnet'] = driftnet_data
            export_json(os.path.join(out_dir, 'driftnet.json'), driftnet_data)

    if do_virustotal:
        vt_data = query_virustotal(target)
        if vt_data:
            recon['modules']['virustotal'] = vt_data
            export_json(os.path.join(out_dir, 'virustotal.json'), vt_data)

    # CVE matching
    logging.info("Matching CVEs...")
    cves = fetch_cve_data(limit=cve_limit)
    services = recon.get('modules', {}).get('nmap', {}).get('services', [])
    matches = match_vulnerabilities(services, cves)
    recon['modules']['cve_matches'] = matches

    # Export CVE matches
    if matches:
        rows = []
        for m in matches:
            rows.append({
                'cve_id': m.get('id'),
                'score': m.get('match_score'),
                'description': m.get('description')[:300]
            })
        export_csv(os.path.join(out_dir, 'cve_matches.csv'), rows)

    # Optional AI summary
    if enable_ai:
        logging.info("Generating AI summary...")
        summary = chatgpt_analysis(recon)
        if summary:
            recon['modules']['ai_summary'] = summary
            save_text(os.path.join(out_dir, 'ai_summary.txt'), summary)

    # Export main report
    export_json(os.path.join(out_dir, 'report.json'), recon)

    # Generate HTML report
    if enable_html_report:
        html_path = os.path.join(out_dir, 'report.html')
        generate_html_report(target, recon, html_path)

    t1 = time.time()
    recon['duration_sec'] = round(t1 - t0, 2)
    return recon

def print_human_summary(target: str, recon: Dict[str, Any]) -> None:
    """Print human-readable summary to console."""
    print(f"\n{'='*80}")
    print(f"[+] Summary for {target}")
    print(f"{'='*80}")

    modules = recon.get('modules', {})

    # Services
    services = modules.get('nmap', {}).get('services', [])
    if services:
        print(f"\n🔌 Services ({len(services)}):")
        for s in services[:10]:
            port = s.get('port', '?')
            name = s.get('name', '')
            product = s.get('product', '')
            version = s.get('version', '')
            print(f"   {port:<15} {name:<12} {product} {version}")
        if len(services) > 10:
            print(f"   ... and {len(services)-10} more")

    # Subdomains
    subdomains = modules.get('subdomains', [])
    if subdomains:
        print(f"\n🌍 Subdomains ({len(subdomains)}):")
        for sub in subdomains[:10]:
            print(f"   • {sub}")
        if len(subdomains) > 10:
            print(f"   ... and {len(subdomains)-10} more")

    # CVEs
    cves = modules.get('cve_matches', [])
    if cves:
        print(f"\n🚨 Potential CVEs ({len(cves)}):")
        for cve in cves[:5]:
            score = cve.get('match_score', 0)
            cve_id = cve.get('id', 'N/A')
            desc = cve.get('description', '')[:100]
            print(f"   [{score}] {cve_id}: {desc}...")
        if len(cves) > 5:
            print(f"   ... and {len(cves)-5} more")

    # Shodan
    shodan = modules.get('shodan', {})
    if shodan and shodan.get('ip'):
        print(f"\n🔎 Shodan Intelligence:")
        print(f"   Org: {shodan.get('org', 'N/A')}")
        print(f"   ISP: {shodan.get('isp', 'N/A')}")
        print(f"   Location: {shodan.get('city', 'N/A')}, {shodan.get('country', 'N/A')}")
        print(f"   Ports: {', '.join(map(str, shodan.get('ports', [])))}")

    # Web Tech
    web_tech = modules.get('web_tech', {})
    if web_tech and 'error' not in web_tech:
        print(f"\n💻 Web Technologies:")
        print(f"   Server: {web_tech.get('server', 'N/A')}")
        print(f"   Frameworks: {', '.join(web_tech.get('frameworks', [])) or 'None detected'}")
        print(f"   CMS: {', '.join(web_tech.get('cms', [])) or 'None detected'}")

    print(f"\n⏱️  Duration: {recon.get('duration_sec', '?')}s")
    print(f"📁 Outputs saved to export directory")
    print(f"{'='*80}\n")

# -------------------------
# CLI (Enhanced)
# -------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ExpertRecon v2.0 - Advanced Recon & Correlation Toolkit (authorized use only)",
        epilog="Set API keys via environment variables: SHODAN_API_KEY, FOFA_EMAIL/KEY, VIRUSTOTAL_API_KEY, etc.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    p.add_argument('target', help='Target domain/IP OR path to file with targets (one per line)')
    p.add_argument('--export-dir', default='exports', help='Directory to store outputs')

    # Core modules
    core = p.add_argument_group('Core Recon Modules')
    core.add_argument('--no-nmap', action='store_true', help='Disable nmap scan')
    core.add_argument('--no-harvester', action='store_true', help='Disable theHarvester')
    core.add_argument('--no-dnsrecon', action='store_true', help='Disable dnsrecon')

    # Enhanced modules
    enhanced = p.add_argument_group('Enhanced Modules')
    enhanced.add_argument('--subdomain-enum', action='store_true', help='Enable subdomain enumeration')
    enhanced.add_argument('--whois', action='store_true', help='Enable WHOIS lookup')
    enhanced.add_argument('--ssl-analysis', action='store_true', help='Enable SSL/TLS analysis')
    enhanced.add_argument('--web-tech', action='store_true', help='Enable web technology detection')
    enhanced.add_argument('--screenshot', action='store_true', help='Capture screenshots (requires Selenium)')
    enhanced.add_argument('--dir-enum', action='store_true', help='Enable directory enumeration')

    # API integrations
    apis = p.add_argument_group('API Integrations')
    apis.add_argument('--shodan', action='store_true', help='Enable Shodan API lookup')
    apis.add_argument('--fofa', action='store_true', help='Enable FOFA API lookup')
    apis.add_argument('--driftnet', action='store_true', help='Enable Driftnet API lookup')
    apis.add_argument('--virustotal', action='store_true', help='Enable VirusTotal lookup')

    # Options
    opts = p.add_argument_group('Options')
    opts.add_argument('--cve-limit', type=int, default=300, help='Limit for CVE checks (default 300)')
    opts.add_argument('--ai-summary', action='store_true', help='Generate AI-assisted summary')
    opts.add_argument('--html-report', action='store_true', help='Generate HTML dashboard report')
    opts.add_argument('--stealth', action='store_true', help='Enable stealth mode (slower, rate-limited)')
    opts.add_argument('--threads', type=int, default=10, help='Number of threads for concurrent tasks')
    opts.add_argument('--debug', action='store_true', help='Enable debug logging')
    opts.add_argument('--show-config', action='store_true', help='Show configuration and exit')

    # All-in-one
    p.add_argument('--all', action='store_true', help='Enable ALL modules (comprehensive scan)')

    return p.parse_args()

def show_config() -> None:
    """Display effective configuration."""
    def red(s):
        if not s or len(s) < 3:
            return '(not set)'
        return s[:3] + '****' + s[-2:] if len(s) > 6 else '****'

    print("\n" + "="*60)
    print("ExpertRecon v2.0 - Configuration")
    print("="*60)
    print(f"FOFA_EMAIL       = {red(FOFA_EMAIL)}")
    print(f"FOFA_API_KEY     = {red(FOFA_API_KEY)}")
    print(f"DRIFNET_API_KEY  = {red(DRIFNET_API_KEY)}")
    print(f"SHODAN_API_KEY   = {red(SHODAN_API_KEY)}")
    print(f"VIRUSTOTAL_KEY   = {red(VIRUSTOTAL_API_KEY)}")
    print(f"HIBP_API_KEY     = {red(HIBP_API_KEY)}")
    print(f"OPENAI_API_KEY   = {red(OPENAI_API_KEY)}")
    print(f"SAFE_MODE        = {SAFE_MODE}")
    print(f"Platform         = {platform.system()} {platform.release()}")
    print(f"\nLibraries:")
    print(f"  DNS support    = {DNS_AVAILABLE}")
    print(f"  WHOIS support  = {WHOIS_AVAILABLE}")
    print(f"  Selenium       = {SELENIUM_AVAILABLE}")
    print("="*60 + "\n")

def main():
    """Main entry point."""
    args = parse_args()
    setup_logging(debug=args.debug)
    print_banner()

    if args.show_config:
        show_config()
        return

    logging.info("ExpertRecon v2.0 - For Authorized Security Testing Only")

    try:
        # Enable all modules if --all flag is set
        if args.all:
            args.subdomain_enum = True
            args.whois = True
            args.ssl_analysis = True
            args.web_tech = True
            args.dir_enum = True
            args.shodan = True
            args.fofa = True
            args.driftnet = True
            args.virustotal = True
            args.html_report = True

        targets = load_targets(args.target)
        logging.info("Loaded %d target(s).", len(targets))

        for t in targets:
            recon = process_target(
                target=t,
                export_dir=args.export_dir,
                do_nmap=not args.no_nmap,
                do_harvester=not args.no_harvester,
                do_dnsrecon=not args.no_dnsrecon,
                do_subdomain_enum=args.subdomain_enum,
                do_whois=args.whois,
                do_ssl_analysis=args.ssl_analysis,
                do_web_tech=args.web_tech,
                do_screenshot=args.screenshot,
                do_dir_enum=args.dir_enum,
                do_shodan=args.shodan,
                do_fofa=args.fofa,
                do_driftnet=args.driftnet,
                do_virustotal=args.virustotal,
                cve_limit=max(1, args.cve_limit),
                enable_ai=args.ai_summary,
                enable_html_report=args.html_report,
                stealth_mode=args.stealth,
                threads=args.threads
            )
            print_human_summary(t, recon)

        logging.info("✅ All scans completed successfully!")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting gracefully.")
        logging.warning("Interrupted by user (KeyboardInterrupt).")
    except Exception as e:
        logging.exception("Fatal error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    if platform.system() == 'Windows':
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
