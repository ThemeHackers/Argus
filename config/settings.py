# config/settings.py

# Directory where results will be saved
RESULTS_DIR = "results"

# Default timeout for network requests (in seconds)
DEFAULT_TIMEOUT = 10
# config/settings.py

USER_AGENT = 'Mozilla/5.0 (compatible; ArgusBot/1.0; )'

# API Keys for third-party services (add your own keys)
API_KEYS = {
    "VIRUSTOTAL_API_KEY": "25f612d52c1f3b34a71ca239f26bef311325e04f7ca8b36857bee05810b995e8",  # API key for VirusTotal
    "SHODAN_API_KEY": "VmQnkUgcbyW8pV5C7UxA08ocY0T7yZG4",         # API key for Shodan
    "GOOGLE_API_KEY": "AIzaSyCCWTVA-EN3F9lY-NXttU0u8fkjWk-pvtU",     # API key for Google
    "CENSYS_API_ID": "3b1b9ff7-93ee-4264-8622-12529e65c828",           # API ID for Censys
    "CENSYS_API_SECRET": "b9Dcm36ELOvOyQYCcDt5MqZZxMnmv1kl",    # API Secret for Censys

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
