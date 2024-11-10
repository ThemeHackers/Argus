# config/settings.py
# for argus cli version

# Directory where results will be saved
RESULTS_DIR = "results"

# Default timeout for network requests (in seconds)
DEFAULT_TIMEOUT = 35

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59'

# API Keys for third-party services (add your own keys)
API_KEYS = {
    "VIRUSTOTAL_API_KEY": "",  # API key for VirusTotal
    "SHODAN_API_KEY": "",         # API key for Shodan
    "GOOGLE_API_KEY": "",     # API key for Google
    "CENSYS_API_ID": "",           # API ID for Censys
    "CENSYS_API_SECRET": "",    # API Secret for Censys

}

# Export Settings for Reports
EXPORT_SETTINGS = {
    "enable_txt_export": True,   # Enable or disable TXT report generation
    "enable_csv_export": False    # Enable or disable CSV report generation (Still in Developpement)
}

# Logging Configuration
LOG_SETTINGS = {
    "enable_logging": True,
    "log_file": "argus.log",                   # Log file name
    "log_level": "INFO"                        # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
}

# HTTP Headers for Modules that Require Requests
HEADERS = {
    "User-Agent": "Argus-Scanner/1.0",
    "Accept-Language": "en-US,en;q=0.9"
}
