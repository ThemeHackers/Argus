# config/app_settings.py
# for argus webapp version

import json
import os
CONFIG_FILE_PATH = os.path.join(os.path.dirname(__file__), 'settings.json')

with open(CONFIG_FILE_PATH, 'r') as config_file:
    
    config = json.load(config_file)

RESULTS_DIR = config["RESULTS_DIR"]
DEFAULT_TIMEOUT = config["DEFAULT_TIMEOUT"]
API_KEYS = config["API_KEYS"]
EXPORT_SETTINGS = config["EXPORT_SETTINGS"]
LOG_SETTINGS = config["LOG_SETTINGS"]
HEADERS = config["HEADERS"]

