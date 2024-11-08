# GNU GENERAL PUBLIC LICENSE 
# Version 3, 29 June 2007
# Copyright © 2007 Free Software Foundation, Inc. <http://fsf.org/>
import os
import sys
import requests
from rich.console import Console
from rich.table import Table
from colorama import Fore, init

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.util import clean_domain_input, validate_domain
from config.settings import DEFAULT_TIMEOUT  

init(autoreset=True)
console = Console()

def banner():
    console.print(Fore.GREEN + """
    =============================================
          Argus - DNS Over HTTPS (DoH) Check
    =============================================
    """)

def check_dns_over_https(domain, record_type):
    try:
        api_url = f"https://dns.google/resolve?name={domain}&type={record_type}"
        response = requests.get(api_url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            if "Answer" in data:
                return "Supported"
            return "Not Supported"
        else:
            return f"Error: HTTP {response.status_code} - {response.reason}"
    except requests.Timeout:
        return "Error: Request timed out"
    except requests.ConnectionError:
        return "Error: Network connection issue"
    except requests.RequestException as e:
        return f"Error: {str(e)}"

def display_dns_over_https(results):
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Record Type", style="cyan", justify="left")
    table.add_column("DoH Status", style="cyan", justify="left")
    
    for record_type, status in results.items():
        table.add_row(record_type, status)
    
    console.print(table)

def main(target):
    banner()
    domain = clean_domain_input(target)

    if not validate_domain(domain):
        console.print(Fore.RED + "[!] Invalid domain format. Please check the domain and try again.")
        return

    console.print(Fore.WHITE + f"[*] Checking DNS over HTTPS support for: {domain}")
    
    # List of all standard DNS record types
    record_types = [
        "A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", 
        "CSYNC", "DHCID", "DLV", "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO", 
        "HIP", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC", "MX", "NAPTR", "NS", 
        "NSEC", "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR", "RRSIG", "RP", "SIG", 
        "SMIMEA", "SOA", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", 
        "TXT", "URI"
    ]
    results = {}

    for record_type in record_types:
        doh_status = check_dns_over_https(domain, record_type)
        results[record_type] = doh_status if doh_status else "Error"

    display_dns_over_https(results)
    console.print(Fore.CYAN + "[*] DNS Over HTTPS check completed.")

if __name__ == "__main__":
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        main(target)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass a domain or URL.")
        sys.exit(1)
