#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Recon & Correlation Toolkit — Enhanced (2025-08)
Author: sudo3rs

Highlights
- Solid error handling & structured logging (file + console, rotating)
- Safer-by-default design (no exploitation; optional/gated stubs)
- Config via environment variables (with --show-config to verify)
- Dependency checks (nmap, theHarvester, dnsrecon)
- FOFA + Driftnet API integrations with timeouts, retries, graceful failures
- CVE fetch caching (session-level), quick fuzzy matching to discovered services
- Human-readable summary + JSON/CSV exports per target
- Progress bars for steps; clean KeyboardInterrupt handling
- Windows-friendly subprocess invocation
- Optional OpenAI-assisted summarization (off by default; gated with flag)
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
import logging
import platform
import argparse
import subprocess
from datetime import datetime
from logging.handlers import RotatingFileHandler

from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm

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

                       v1 by sudo3rs
    """
    print(banner)

# -------------------------
# Constants & Configuration
# -------------------------
CVE_API_URL = 'https://cve.circl.lu/api/last'
FOFA_API_URL = 'https://fofa.info/api/v1/search/all'
DRIFNET_API_URL = 'https://api.driftnet.io/v1/search'
OPENAI_CHAT_URL = 'https://api.openai.com/v1/chat/completions'

DEFAULT_TIMEOUT = 25
CONNECT_TIMEOUT = 10
MAX_RESULTS = 20

# Read secrets from env (preferred over hardcoding)
FOFA_EMAIL = os.getenv('FOFA_EMAIL', 'Your Email')
FOFA_API_KEY = os.getenv('FOFA_API_KEY', 'Your Key')
DRIFNET_API_KEY = os.getenv('DRIFNET_API_KEY', 'Your Key')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'Your Key')

# Safe mode blocks any offensive action by default
SAFE_MODE = os.getenv('SAFE_MODE', '1') in ('1', 'true', 'True', 'yes')

# -------------------------
# Logging Setup
# -------------------------
def setup_logging(debug: bool = False, log_file: str = 'recon.log') -> None:
    level = logging.DEBUG if debug else logging.INFO
    logger = logging.getLogger()
    logger.setLevel(level)

    # Clear existing handlers (if re-running)
    for h in list(logger.handlers):
        logger.removeHandler(h)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch_fmt = logging.Formatter('[%(levelname)s] %(message)s')
    ch.setFormatter(ch_fmt)

    # Rotating file handler
    fh = RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3, encoding='utf-8')
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
_CVE_CACHE: Optional[List[Dict[str, Any]]]= None

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
            shell=False  # keep safer & Windows-compatible if tool on PATH
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
            f.write("")  # create empty file
        return
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def tokens_from_text(text: str) -> List[str]:
    text = (text or "").lower()
    # keep alphanum + dot/dash (so "apache-httpd/2.4.58" -> ["apache", "httpd", "2.4.58"])
    parts = re.split(r'[^a-z0-9.\-]+', text)
    return [p for p in parts if p]

# -------------------------
# Data Fetchers
# -------------------------
def fetch_cve_data(limit: int = 200) -> List[Dict[str, Any]]:
    """Fetch latest CVEs; cached per run. Limit for speed."""
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

def query_fofa(target: str, size: int = MAX_RESULTS) -> List[Dict[str, Any]]:
    """Search FOFA for the host; returns list of dicts for readability."""
    if not FOFA_EMAIL or not FOFA_API_KEY or FOFA_EMAIL == 'Your Email' or FOFA_API_KEY == 'Your Key':
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
        # Convert FOFA list rows (depending on fields) into dicts
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
    if not DRIFNET_API_KEY or DRIFNET_API_KEY == 'Your Key':
        logging.info("Driftnet not configured; skipping.")
        return []
    try:
        headers = {'Authorization': f'Bearer {DRIFNET_API_KEY}'}
        params = {'query': target, 'size': size}
        resp = SESSION.get(DRIFNET_API_URL, headers=headers, params=params, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
        if resp.status_code != 200:
            logging.error("Driftnet error: %s", resp.text[:300])
            return []
        payload = resp.json()
        data = payload.get('data', [])
        # normalize to dict list
        norm = data if isinstance(data, list) else [data]
        return [d if isinstance(d, dict) else {'result': d} for d in norm]
    except Exception as e:
        logging.error("Exception querying Driftnet: %s", e)
        return []

# -------------------------
# Recon Modules
# -------------------------
def perform_nmap_scan(target: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run nmap -sV to identify services.
    Returns dict: { 'raw': str, 'services': [ {port, name, product, version, info} ] }
    """
    install_hint = "Install Nmap and add it to PATH (Windows: https://nmap.org/download)."
    nmap = which_or_hint('nmap', install_hint)
    if not nmap:
        return {'raw': '', 'services': []}

    args = [nmap, '-sV', '--version-light', target]
    if extra_args:
        args.extend(extra_args)

    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("Nmap scan failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or '', 'services': []}

    services = []
    # Parse typical nmap service lines: "PORT   STATE SERVICE VERSION"
    for line in out.splitlines():
        # Example: "80/tcp open http Apache httpd 2.4.58 ((Win64))"
        m = re.match(r'^(\d+/\w+)\s+open\s+([a-z0-9\-\_]+)\s+(.*)$', line.strip(), re.I)
        if m:
            port, name, rest = m.groups()
            product = None
            version = None
            info = rest.strip()
            # Try splitting product/version heuristically
            # e.g., "Apache httpd 2.4.58 ((Win64))"
            parts = rest.split()
            if len(parts) >= 2:
                product = " ".join(parts[:-1])
                version = parts[-1]
                # If version looks noisy, keep as info only
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
    """
    Run theHarvester (Google) for OSINT.
    Returns dict: { 'raw': str }
    """
    install_hint = "Install theHarvester (pipx/pip) and ensure 'theharvester' is on PATH."
    exe = which_or_hint('theharvester', install_hint)
    if not exe:
        return {'raw': ''}

    args = [exe, '-d', target, '-b', 'google']
    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("theHarvester failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or ''}
    return {'raw': out}

def perform_dnsrecon(target: str) -> Dict[str, Any]:
    """
    Run dnsrecon basic scan.
    Returns dict: { 'raw': str }
    """
    install_hint = "Install dnsrecon (pipx/pip) and ensure 'dnsrecon' is on PATH."
    exe = which_or_hint('dnsrecon', install_hint)
    if not exe:
        return {'raw': ''}

    args = [exe, '-d', target]
    code, out, err = run_cmd(args, timeout=300)
    if code != 0:
        logging.error("dnsrecon failed (%s): %s", code, err.strip()[:300])
        return {'raw': out or ''}
    return {'raw': out}

# -------------------------
# Matching / Correlation
# -------------------------
def match_vulnerabilities(
    services: List[Dict[str, Any]],
    cve_data: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Very lightweight fuzzy matcher:
    - build token set from discovered product/name/version
    - check if tokens appear in CVE summary (lowercased)
    This is heuristic (may include false positives). Treat as hints.
    """
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
        # any token overlap?
        if summary and any(t in summary for t in tokens if len(t) > 2):
            candidates.append({
                'id': cid,
                'description': cve.get('summary', ''),
                'references': refs
            })
    return candidates

# -------------------------
# Optional: Metasploit Stub (Gated)
# -------------------------
def exploit_with_metasploit_stub(target: str, enabled: bool, module: str, payload: str, lhost: str, lport: int):
    """
    Stub only. Does NOT run exploits by default.
    To enable, pass --allow-offensive AND set env AUTH_TEST=YES and SAFE_MODE=0.
    """
    if not enabled:
        logging.info("Offensive actions disabled (no flag). Skipping metasploit stub.")
        return

    if SAFE_MODE or os.getenv('AUTH_TEST', 'NO') != 'YES':
        logging.warning("SAFE MODE / AUTH_TEST gate blocked offensive action for %s. "
                        "To proceed (authorized testing only): set SAFE_MODE=0 and AUTH_TEST=YES.", target)
        return

    exe = shutil.which('msfconsole')
    if not exe:
        logging.error("Metasploit not found on PATH. Install metasploit-framework before using.")
        return

    script = (
        f"use {module}; "
        f"set RHOSTS {target}; "
        f"set PAYLOAD {payload}; "
        f"set LHOST {lhost}; "
        f"set LPORT {lport}; "
        f"check; "
        f"show options; "
        f"back"
    )
    logging.info("Launching Metasploit console (check only) for authorized test target: %s", target)
    code, out, err = run_cmd([exe, '-q', '-x', script], timeout=600)
    if code != 0:
        logging.error("Metasploit error (%s): %s", code, err.strip()[:400])
    else:
        logging.info("Metasploit output (truncated): %s", (out or "")[:600])

# -------------------------
# Optional: OpenAI Summarization (Gated)
# -------------------------
def chatgpt_analysis(data: Dict[str, Any], model: str = "gpt-4o-mini") -> Optional[str]:
    if not OPENAI_API_KEY or OPENAI_API_KEY == 'Your Key':
        logging.info("OpenAI API key not set; skipping AI analysis.")
        return None
    try:
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {OPENAI_API_KEY}',
        }
        prompt = (
            "Summarize the following recon results into 3 sections:\n"
            "1) Key exposed services (with ports)\n"
            "2) Potential risks (short, not definitive)\n"
            "3) Suggested next steps (defensive & validation)\n\n"
            f"DATA:\n{json.dumps(data)[:6000]}"
        )
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 300,
            "temperature": 0.2,
        }
        resp = SESSION.post(OPENAI_CHAT_URL, headers=headers, json=payload, timeout=(CONNECT_TIMEOUT, DEFAULT_TIMEOUT))
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
    p = single_or_file.strip()
    if os.path.isfile(p):
        with open(p, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    return [p]

# -------------------------
# Main Orchestration
# -------------------------
def process_target(
    target: str,
    export_dir: str,
    do_nmap: bool,
    do_harvester: bool,
    do_dnsrecon: bool,
    do_fofa: bool,
    do_driftnet: bool,
    cve_limit: int,
    enable_ai: bool,
    offensive: bool,
    msf_module: str,
    msf_payload: str,
    msf_lhost: str,
    msf_lport: int
) -> Dict[str, Any]:
    t0 = time.time()
    out_dir = os.path.join(export_dir, target.replace('/', '_'))
    os.makedirs(out_dir, exist_ok=True)

    recon = {'target': target, 'timestamp': datetime.utcnow().isoformat()+'Z', 'modules': {}}

    steps = []
    if do_nmap: steps.append('nmap')
    if do_harvester: steps.append('theharvester')
    if do_dnsrecon: steps.append('dnsrecon')

    # Run modules with progress bar
    for step in tqdm(steps, desc=f"Recon: {target}", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
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

    # APIs (no progress bar to keep it simple)
    if do_fofa:
        fofa = query_fofa(target)
        recon['modules']['fofa'] = fofa
        export_json(os.path.join(out_dir, 'fofa.json'), fofa)

    if do_driftnet:
        dr = query_driftnet(target)
        recon['modules']['driftnet'] = dr
        export_json(os.path.join(out_dir, 'driftnet.json'), dr)

    # CVEs + matching
    cves = fetch_cve_data(limit=cve_limit)
    services = recon.get('modules', {}).get('nmap', {}).get('services', [])
    matches = match_vulnerabilities(services, cves)
    recon['modules']['cve_matches'] = matches

    # Export matches as CSV too
    rows = []
    for m in matches:
        rows.append({'cve_id': m.get('id'), 'description': m.get('description')[:300]})
    export_csv(os.path.join(out_dir, 'cve_matches.csv'), rows)

    # Optional AI summary
    if enable_ai:
        summary = chatgpt_analysis(recon)
        if summary:
            recon['modules']['ai_summary'] = summary
            save_text(os.path.join(out_dir, 'ai_summary.txt'), summary)

    # Optional (gated) Metasploit stub
    if offensive:
        exploit_with_metasploit_stub(
            target=target,
            enabled=offensive,
            module=msf_module,
            payload=msf_payload,
            lhost=msf_lhost,
            lport=msf_lport
        )

    # Summary file
    export_json(os.path.join(out_dir, 'report.json'), recon)
    t1 = time.time()
    recon['duration_sec'] = round(t1 - t0, 2)
    return recon

def print_human_summary(target: str, recon: Dict[str, Any]) -> None:
    print(f"\n[+] Summary for {target}")
    nmap = recon.get('modules', {}).get('nmap', {})
    services = nmap.get('services', []) or []
    if services:
        print("  Services:")
        for s in services:
            port = s.get('port') or '?'
            name = s.get('name') or ''
            product = s.get('product') or ''
            version = s.get('version') or ''
            info = s.get('info') or ''
            line = f"   - {port:<10} {name:<10} {product} {version} | {info}".strip()
            print(line)
    else:
        print("  Services: (none parsed or nmap missing)")

    matches = recon.get('modules', {}).get('cve_matches', []) or []
    if matches:
        print(f"  Potential CVE matches (heuristic): {len(matches)}")
        for m in matches[:10]:
            print(f"   - {m.get('id')}: {m.get('description')[:140]}{'...' if len(m.get('description',''))>140 else ''}")
        if len(matches) > 10:
            print(f"   ... and {len(matches)-10} more (see export).")
    else:
        print("  Potential CVE matches: none (heuristic only)")

    print(f"  Duration: {recon.get('duration_sec', '?')}s")
    print("  Exports: report.json, cve_matches.csv and module outputs saved under export dir.")

# -------------------------
# CLI
# -------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Recon & Correlation Toolkit (authorized use only)",
        epilog="Tip: set environment variables FOFA_EMAIL/FOFA_API_KEY, DRIFNET_API_KEY, OPENAI_API_KEY."
    )
    p.add_argument('target', help='A target domain/IP OR a path to a file of targets (one per line)')
    p.add_argument('--export-dir', default='exports', help='Directory to store outputs')
    p.add_argument('--no-nmap', action='store_true', help='Disable nmap module')
    p.add_argument('--no-harvester', action='store_true', help='Disable theHarvester module')
    p.add_argument('--no-dnsrecon', action='store_true', help='Disable dnsrecon module')
    p.add_argument('--fofa', action='store_true', help='Enable FOFA API lookup')
    p.add_argument('--driftnet', action='store_true', help='Enable Driftnet API lookup')
    p.add_argument('--cve-limit', type=int, default=200, help='Limit for latest CVEs to check (default 200)')
    p.add_argument('--ai-summary', action='store_true', help='Enable OpenAI-assisted summary (requires OPENAI_API_KEY)')
    p.add_argument('--debug', action='store_true', help='Enable debug logging')
    p.add_argument('--show-config', action='store_true', help='Show effective config (keys redacted) and exit')

    # Gated offensive stub (won’t run unless flags + env)
    p.add_argument('--allow-offensive', action='store_true', help='Allow gated offensive stub (authorized tests only). Requires SAFE_MODE=0 and AUTH_TEST=YES')
    p.add_argument('--msf-module', default='auxiliary/scanner/portscan/tcp', help='Metasploit module (stub uses "check")')
    p.add_argument('--msf-payload', default='windows/meterpreter/reverse_tcp', help='Metasploit payload (not executed unless fully enabled)')
    p.add_argument('--msf-lhost', default='127.0.0.1', help='LHOST for payload (if used)')
    p.add_argument('--msf-lport', type=int, default=4444, help='LPORT for payload (if used)')
    return p.parse_args()

def show_config() -> None:
    def red(s): 
        if not s or s in ('Your Key','Your Email'): return '(not set)'
        return s[:3] + '****' + s[-2:] if len(s) > 6 else '****'
    print("\nEffective configuration:")
    print(f"  FOFA_EMAIL       = {red(FOFA_EMAIL)}")
    print(f"  FOFA_API_KEY     = {red(FOFA_API_KEY)}")
    print(f"  DRIFNET_API_KEY  = {red(DRIFNET_API_KEY)}")
    print(f"  OPENAI_API_KEY   = {red(OPENAI_API_KEY)}")
    print(f"  SAFE_MODE        = {SAFE_MODE}")
    print(f"  Platform         = {platform.system()} {platform.release()}")
    print("")

def main():
    args = parse_args()
    setup_logging(debug=args.debug)
    print_banner()

    if args.show_config:
        show_config()
        return

    # Authorized-use reminder
    logging.info("Use this tool only on systems you are explicitly authorized to assess.")

    try:
        targets = load_targets(args.target)
        logging.info("Loaded %d target(s).", len(targets))

        for t in targets:
            recon = process_target(
                target=t,
                export_dir=args.export_dir,
                do_nmap=not args.no_nmap,
                do_harvester=not args.no_harvester,
                do_dnsrecon=not args.no_dnsrecon,
                do_fofa=args.fofa,
                do_driftnet=args.driftnet,
                cve_limit=max(1, args.cve_limit),
                enable_ai=args.ai_summary,
                offensive=args.allow_offensive,
                msf_module=args.msf_module,
                msf_payload=args.msf_payload,
                msf_lhost=args.msf_lhost,
                msf_lport=args.msf_lport
            )
            print_human_summary(t, recon)

        logging.info("Done.")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting gracefully.")
        logging.warning("Interrupted by user (KeyboardInterrupt).")
    except Exception as e:
        logging.exception("Fatal error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    # Ensure Ctrl+C works well on Windows too
    if platform.system() == 'Windows':
        signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
