import os
import sys
import requests
import re
import time
from rich.console import Console
from rich.table import Table
from colorama import init, Fore

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import API_KEYS
from utils.util import clean_url

init(autoreset=True)
console = Console()

GOOGLE_API_KEY = API_KEYS.get("GOOGLE_API_KEY")

def banner():
    console.print("""
[green]
    =============================================
           Argus - Performance Monitoring
    =============================================
[/green]
    """)

def validate_url(url):
    url_pattern = re.compile(
        r'^(https?://)?'          
        r'(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'  
        r'(:[0-9]{1,5})?'         
        r'(/.*)?$'                
    )
    return re.match(url_pattern, url) is not None

def get_performance_metrics(url):
    try:
        clean_target = clean_url(url)
        if not GOOGLE_API_KEY:
            console.print("[red][!] Google API key not configured. Please set your API key in the configuration file.[/red]")
            return None

        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={clean_target}&strategy=mobile&key={GOOGLE_API_KEY}"
        response = requests.get(api_url)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 403:
            console.print("[red][!] Access Denied. Please check if your Google API key has the correct permissions.[/red]")
            return None
        elif response.status_code == 400:
            console.print("[red][!] Bad Request. The URL or parameters might be incorrect. Please verify the URL and try again.[/red]")
            return None
        else:
            console.print(f"[red][!] Error: Received status code {response.status_code} from the API. Please verify your API key and target URL.[/red]")
            return None

    except requests.RequestException as e:
        console.print(f"[red][!] Error retrieving performance metrics: {e}[/red]")
        return None

def display_performance_metrics(metrics):
    if metrics:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan", justify="left")
        table.add_column("Value", style="green")

        performance_score = metrics.get("lighthouseResult", {}).get("categories", {}).get("performance", {}).get("score", "N/A")
        table.add_row("Performance Score", str(performance_score * 100 if isinstance(performance_score, float) else "N/A"))

        console.print(table)
    else:
        console.print("[red][!] No performance data to display.[/red]")

# 1. Fetch additional insights such as FCP and LCP
def get_additional_insights(metrics):
    try:
        fcp = metrics.get("lighthouseResult", {}).get("audits", {}).get("first-contentful-paint", {}).get("displayValue", "N/A")
        lcp = metrics.get("lighthouseResult", {}).get("audits", {}).get("largest-contentful-paint", {}).get("displayValue", "N/A")

        console.print(f"First Contentful Paint (FCP): {fcp}")
        console.print(f"Largest Contentful Paint (LCP): {lcp}")
    except Exception as e:
        console.print(Fore.RED + f"[!] Error extracting insights: {e}")

# 2. Add delay to handle multiple requests
def process_urls_with_delay(targets, delay=2):
    for url in targets:
        console.print(Fore.WHITE + f"[*] Fetching performance metrics for {url} with delay...")
        metrics = get_performance_metrics(url)
        if metrics:
            display_performance_metrics(metrics)
            get_additional_insights(metrics)
        else:
            console.print(Fore.RED + f"[!] Failed to retrieve metrics for {url}.")
        
        time.sleep(delay)  # Introduce delay between requests

def main(targets):
    banner()
    if not GOOGLE_API_KEY:
        console.print(Fore.RED + "[!] Google API key is not set. Please set it in config/settings.py or as an environment variable.")
        return  # Changed from sys.exit(1) to return

    cleaned_targets = []
    for target in targets:
        cleaned = clean_url(target)
        if validate_url(cleaned):
            cleaned_targets.append(cleaned)
        else:
            console.print(Fore.RED + f"[!] Invalid URL format: {target}")

    if not cleaned_targets:
        console.print(Fore.RED + "[!] No valid URLs to scan.")
        return  # Changed from sys.exit(1) to return

    collected_metrics = []
    for url in cleaned_targets:
        console.print(Fore.WHITE + f"[*] Fetching performance metrics for {url}...")
        metrics = get_performance_metrics(url)
        if metrics:
            display_performance_metrics(metrics)
            get_additional_insights(metrics)
            performance_score = metrics.get("lighthouseResult", {}).get("categories", {}).get("performance", {}).get("score", "N/A")
            fcp = metrics.get("lighthouseResult", {}).get("audits", {}).get("first-contentful-paint", {}).get("displayValue", "N/A")
            lcp = metrics.get("lighthouseResult", {}).get("audits", {}).get("largest-contentful-paint", {}).get("displayValue", "N/A")
            collected_metrics.append({"url": url, "performance_score": performance_score, "fcp": fcp, "lcp": lcp})
        else:
            console.print(Fore.RED + f"[!] Failed to retrieve metrics for {url}.")
    
    console.print(Fore.CYAN + "[*] Performance monitoring completed.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            main(sys.argv[1:])
        except KeyboardInterrupt:
            console.print(Fore.RED + "\n[!] Process interrupted by user.")
            sys.exit(1)  # You can keep sys.exit here if a manual interruption occurs
        except Exception as e:
            console.print(Fore.RED + f"\n[!] An unexpected error occurred: {e}")
            sys.exit(1)
    else:
        console.print(Fore.RED + "[!] No target provided. Please pass one or more URLs.")
