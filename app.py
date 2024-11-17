from flask import Flask, render_template, request, redirect, url_for , get_flashed_messages , jsonify , flash , send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sys
import subprocess
import os
import json
import requests
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.app_settings import API_KEYS
from config.settings import RESULTS_DIR


app = Flask(__name__)
CONFIG_FILE_PATH = os.path.join(app.root_path, 'config', 'settings.json')

app.config['SECRET_KEY'] = os.urandom(24).hex()

# Define tools with updated module numbers
tools = [
    # Network & Infrastructure 
    {'number': '1', 'name': 'Associated Hosts', 'script': 'associated_hosts.py', 'section': 'Network & Infrastructure'},
    {'number': '2', 'name': 'DNS Over HTTPS', 'script': 'dns_over_https.py', 'section': 'Network & Infrastructure'},
    {'number': '3', 'name': 'DNS Records', 'script': 'dns_records.py', 'section': 'Network & Infrastructure'},
    {'number': '4', 'name': 'DNSSEC Check', 'script': 'dnssec.py', 'section': 'Network & Infrastructure'},
    {'number': '5', 'name': 'Domain Info', 'script': 'domain_info.py', 'section': 'Network & Infrastructure'},
    {'number': '6', 'name': 'Domain Reputation Check', 'script': 'domain_reputation_check.py', 'section': 'Network & Infrastructure'},
    {'number': '7', 'name': 'HTTP/2 and HTTP/3 Support Checker', 'script': 'http2_http3_checker.py', 'section': 'Network & Infrastructure'},
    {'number': '8', 'name': 'IP Info', 'script': 'ip_info.py', 'section': 'Network & Infrastructure'},
    {'number': '9', 'name': 'Open Ports Scan', 'script': 'open_ports.py', 'section': 'Network & Infrastructure'},
    {'number': '10', 'name': 'Server Info', 'script': 'server_info.py', 'section': 'Network & Infrastructure'},
    {'number': '11', 'name': 'Server Location', 'script': 'server_location.py', 'section': 'Network & Infrastructure'},
    {'number': '12', 'name': 'SSL Chain Analysis', 'script': 'ssl_chain.py', 'section': 'Network & Infrastructure'},
    {'number': '13', 'name': 'SSL Expiry Alert', 'script': 'ssl_expiry.py', 'section': 'Network & Infrastructure'},
    {'number': '14', 'name': 'TLS Cipher Suites', 'script': 'tls_cipher_suites.py', 'section': 'Network & Infrastructure'},
    {'number': '15', 'name': 'TLS Handshake Simulation', 'script': 'tls_handshake.py', 'section': 'Network & Infrastructure'},
    {'number': '16', 'name': 'Traceroute', 'script': 'traceroute.py', 'section': 'Network & Infrastructure'},
    {'number': '17', 'name': 'TXT Records', 'script': 'txt_records.py', 'section': 'Network & Infrastructure'},
    {'number': '18', 'name': 'WHOIS Lookup', 'script': 'whois_lookup.py', 'section': 'Network & Infrastructure'},
    {'number': '19', 'name': 'Zone Transfer', 'script': 'zonetransfer.py', 'section': 'Network & Infrastructure'},
    {'number': '20', 'name': 'Network Design Checker', 'script': 'network_design_checker.py', 'section': 'Network & Infrastructure'},
    
    # Web Application Analysis 
    {'number': '21', 'name': 'Archive History', 'script': 'archive_history.py', 'section': 'Web Application Analysis'},
    {'number': '22', 'name': 'Broken Links Detection', 'script': 'broken_links.py', 'section': 'Web Application Analysis'},
    {'number': '23', 'name': 'Carbon Footprint', 'script': 'carbon_footprint.py', 'section': 'Web Application Analysis'},
    {'number': '24', 'name': 'CMS Detection', 'script': 'cms_detection.py', 'section': 'Web Application Analysis'},
    {'number': '25', 'name': 'Cookies Analyzer', 'script': 'cookies.py', 'section': 'Web Application Analysis'},
    {'number': '26', 'name': 'Content Discovery', 'script': 'content_discovery.py', 'section': 'Web Application Analysis'},
    {'number': '27', 'name': 'Crawler', 'script': 'crawler.py', 'section': 'Web Application Analysis'},
    {'number': '28', 'name': 'Robots.txt Analyzer', 'script': 'crawl_rules.py', 'section': 'Web Application Analysis'},
    {'number': '29', 'name': 'Directory Finder', 'script': 'directory_finder.py', 'section': 'Web Application Analysis'},
    {'number': '30', 'name': 'Email Harvesting', 'script': 'email_harvester.py', 'section': 'Web Application Analysis'},
    {'number': '31', 'name': 'Performance Monitoring', 'script': 'performance_monitoring.py', 'section': 'Web Application Analysis'},
    {'number': '32', 'name': 'Quality Metrics', 'script': 'quality_metrics.py', 'section': 'Web Application Analysis'},
    {'number': '33', 'name': 'Redirect Chain', 'script': 'redirect_chain.py', 'section': 'Web Application Analysis'},
    {'number': '34', 'name': 'Sitemap Parsing', 'script': 'sitemap.py', 'section': 'Web Application Analysis'},
    {'number': '35', 'name': 'Social Media Presence Scan', 'script': 'social_media.py', 'section': 'Web Application Analysis'},
    {'number': '36', 'name': 'Technology Stack Detection', 'script': 'technology_stack.py', 'section': 'Web Application Analysis'},
    {'number': '37', 'name': 'Third-Party Integrations', 'script': 'third_party_integrations.py', 'section': 'Web Application Analysis'},
    {'number': '38', 'name': 'WAF Detection NIST', 'script': 'waf_detection_nist.py', 'section': 'Web Application Analysis'},
    {'number': '39', 'name': 'Server Misconfiguration Checker', 'script': 'server_misconfiguration.py', 'section': 'Web Application Analysis'},
    {'number': '40', 'name': 'Backup File Scanner', 'script': 'backup_file_scanner.py', 'section': 'Web Application Analysis'},
    # Security & Threat Intelligence 
    {'number': '41', 'name': 'Censys Reconnaissance', 'script': 'censys.py', 'section': 'Security & Threat Intelligence'},
    {'number': '42', 'name': 'Certificate Authority Recon', 'script': 'certificate_authority_recon.py', 'section': 'Security & Threat Intelligence'},
    {'number': '43', 'name': 'Data Leak Detection', 'script': 'data_leak.py', 'section': 'Security & Threat Intelligence'},
    {'number': '44', 'name': 'Exposed Environment Files Checker', 'script': 'exposed_env_files.py', 'section': 'Security & Threat Intelligence'},
    {'number': '45', 'name': 'Firewall Detection', 'script': 'firewall_detection.py', 'section': 'Security & Threat Intelligence'},
    {'number': '46', 'name': 'Global Ranking', 'script': 'global_ranking.py', 'section': 'Security & Threat Intelligence'},
    {'number': '47', 'name': 'HTTP Headers', 'script': 'http_headers.py', 'section': 'Security & Threat Intelligence'},
    {'number': '48', 'name': 'HTTP Security Features', 'script': 'http_security.py', 'section': 'Security & Threat Intelligence'},
    {'number': '49', 'name': 'Malware & Phishing Check', 'script': 'malware_phishing.py', 'section': 'Security & Threat Intelligence'},
    {'number': '50', 'name': 'Pastebin Monitoring', 'script': 'pastebin_monitoring.py', 'section': 'Security & Threat Intelligence'},
    {'number': '51', 'name': 'Privacy & GDPR Compliance', 'script': 'privacy_gdpr.py', 'section': 'Security & Threat Intelligence'},
    {'number': '52', 'name': 'Security.txt Check', 'script': 'security_txt.py', 'section': 'Security & Threat Intelligence'},
    {'number': '53', 'name': 'Shodan Reconnaissance', 'script': 'shodan.py', 'section': 'Security & Threat Intelligence'},
    {'number': '54', 'name': 'SSL Labs Report', 'script': 'ssl_labs_report.py', 'section': 'Security & Threat Intelligence'},
    {'number': '55', 'name': 'SSL Pinning Check', 'script': 'ssl_pinning_check.py', 'section': 'Security & Threat Intelligence'},
    {'number': '56', 'name': 'Subdomain Enumeration', 'script': 'subdomain_enum.py', 'section': 'Security & Threat Intelligence'},
    {'number': '57', 'name': 'Subdomain Takeover', 'script': 'subdomain_takeover.py', 'section': 'Security & Threat Intelligence'},
    {'number': '58', 'name': 'VirusTotal Scan', 'script': 'virustotal_scan.py', 'section': 'Security & Threat Intelligence'},
]


# Home route
@app.route('/')
def index():
    return render_template('/index.html', tools=tools)

@app.route('/download/<filename>')
def download_result(filename):
    try:
        return send_from_directory(RESULTS_DIR, filename, as_attachment=True)
    except FileNotFoundError:
        flash("The requested file was not found.", "error")

        return redirect(url_for('index'))

@app.route('/check_connection')
def check_connection():
    try:
        # Here, we try to make a request to the server itself to check the server's status.
        response = requests.get("https://argus-0qjo.onrender.com/")  # Replace with your server URL if different
        if response.status_code == 200:
            return jsonify({"status": "online"}), 200
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {e}")
        return jsonify({"status": "offline", "error": str(e)}), 500

# Run selected tool with rate limiting
@app.route('/run_tool', methods=['POST'])
def run_tool():
    tool_number = request.form['tool']
    domain = request.form['domain']
    
    # Find the selected tool
    tool = next((tool for tool in tools if tool['number'] == tool_number), None)
    if not tool:
        return render_template('error.html', error_message="Selected tool not found. Please try again.")

    # Check if the script exists for the tool
    if not tool['script']:
        return render_template('error.html', error_message="This tool does not have an associated script.")
    
    script_path = os.path.join('modules', tool['script'])
    try:
        result = subprocess.run([sys.executable, script_path, domain],
                                capture_output=True, text=True, check=True)
        output = result.stdout
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return render_template('result.html', output=output)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_message="Page not found. Please check the URL."), 404

@app.route('/api_key_status', methods=['GET'])
def check_api_key():
    try:
        with open(CONFIG_FILE_PATH, 'r') as config_file:
            settings = json.load(config_file)
           
        api_keys = settings.get("API_KEYS", {})
        if all(api_keys.values()):
            return jsonify({'api_key_exists': True})
        else:
            return jsonify({'api_key_exists': False})
    except Exception as e:
        return jsonify({'api_key_exists': False, 'error': str(e)})

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        # Capture form data
        new_settings = {
            "RESULTS_DIR": request.form.get('results_dir'),
            "DEFAULT_TIMEOUT": int(request.form.get('default_timeout')),
            "API_KEYS": {
                "VIRUSTOTAL_API_KEY": request.form.get('virustotal_api_key'),
                "SHODAN_API_KEY": request.form.get('shodan_api_key'),
                "GOOGLE_API_KEY": request.form.get('google_api_key'),
                "CENSYS_API_ID": request.form.get('censys_api_id'),
                "CENSYS_API_SECRET": request.form.get('censys_api_secret')
            },
            "EXPORT_SETTINGS": {
                "enable_txt_export": 'enable_txt_export' in request.form,
                "enable_csv_export": 'enable_csv_export' in request.form
            },
            "LOG_SETTINGS": {
                "enable_logging": 'enable_logging' in request.form,
                "log_file": request.form.get('log_file'),
                "log_level": request.form.get('log_level')
            },
            "HEADERS": {
                "User-Agent": request.form.get('headers_user_agent'),
                "Accept-Language": request.form.get('headers_accept_language')
            }
        }

        # Write updated settings to JSON file
        with open(CONFIG_FILE_PATH, 'w') as config_file:
            json.dump(new_settings, config_file, indent=4)
        
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))

    # Load current settings from JSON for form display
    with open(CONFIG_FILE_PATH, 'r') as config_file:
        settings = json.load(config_file)

    return render_template('settings.html', settings=settings)


@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_message="An unexpected error occurred on the server."), 500

if __name__ == '__main__':
    app.run(port=10000, debug=False)


