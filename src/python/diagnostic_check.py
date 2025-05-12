#!/usr/bin/env python3

import os
import json
import sys
import logger

# Optional: import from your helpers module if structured that way
try:
    from logger import log_message
except ImportError:
    def log_message(level, message):
        print(f"[{level}] {message}")

def check_config():
    config_path = os.path.abspath("config/config.json")
    if not os.path.exists(config_path):
        log_message("ERROR", f"Config file not found: {config_path}")
        return False

    with open(config_path, "r") as f:
        try:
            config = json.load(f)
            log_message("INFO", f"Config loaded: {config}")
        except json.JSONDecodeError:
            log_message("ERROR", "Invalid JSON format in config file")
            return False
    return True

def check_log_dir():
    log_path = os.path.abspath("logs/wstt.log")
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        log_message("WARNING", f"Log directory does not exist: {log_dir}")
        return False
    log_message("INFO", f"Log directory exists: {log_dir}")
    return True

def main():
    print("\n[ WSTT Python Environment Check ]")
    if check_config() and check_log_dir():
        print("\n✅ Python environment appears to be working correctly.\n")
    else:
        print("\n❌ One or more checks failed.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
