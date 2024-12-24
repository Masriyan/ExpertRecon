# ExpertRecon

**ExpertRecon** is a powerful reconnaissance and exploitation tool designed for security professionals and ethical hackers. It integrates various reconnaissance techniques and third-party APIs to identify vulnerabilities in target systems.

## Features

- **Target Input:** Accepts single IP/domain or reads from a file.
- **Reconnaissance Tools:**
  - **Nmap:** Scans for open ports and services.
  - **theHarvester:** Gathers email addresses and subdomains.
  - **DNSRecon:** Performs DNS enumeration.
- **Vulnerability Assessment:** Matches reconnaissance data against the latest CVEs.
- **Exploit Automation:** Integrates with Metasploit for automated exploitation.
- **OpenAI Integration:** Provides recommendations for exploitation strategies and risk mitigation.
- **User-Friendly Interface:** Displays progress and results in a clear format.

## Installation

### Prerequisites

- Python 3.x
- Nmap
- theHarvester
- DNSRecon
- Metasploit Framework
- Required Python packages

### Steps to Install

1. **Clone the Repository:**
bash git clone https://github.com/Masriyan/ExpertRecon/expertrecon.git cd expertrecon



2. **Install Required Packages:**
   Create a `requirements.txt` file with the following content:
requests tqdm

   Then run:
bash pip install -r requirements.txt

3. **Install Nmap, theHarvester, and DNSRecon:**
bash sudo apt update sudo apt install nmap theharvester dnsrecon metasploit-framework

## Usage

1. **Run the Script:**
bash python recon_exploit_tool.py

2. **Input Targets:**
   - You can enter a single target IP/domain or provide a path to a file containing multiple targets.

3. **View Progress:**
   - The script will display progress messages as it scans each target and will list any matched vulnerabilities.

## Example Output

[+] Processing target: example.com [+] Scanning example.com with Nmap... [+] Gathering information with theHarvester for example.com... [+] Performing DNS reconnaissance for example.com... [+] Vulnerabilities found for example.com:

CVE ID: CVE-2021-12345, Description: Example vulnerability description.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Make your changes and commit them (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Nmap](https://nmap.org/)
- [theHarvester](https://github.com/laramies/theHarvester)
- [DNSRecon](https://github.com/darkoperator/dnsrecon)
- [Metasploit](https://www.metasploit.com/)
- [OpenAI](https://openai.com/)

Additional Files
requirements.txt

   requests
   tqdm
