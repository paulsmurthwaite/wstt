#!/usr/bin/env python3
"""diagnostic_check.py

A standalone utility to check the WSTT environment configuration.

This script verifies that essential files and directories exist and are correctly
formatted. It checks for the main configuration file, validates its JSON
structure, and ensures that the required logging and capture directories are
present. It is intended as a quick diagnostic tool for developers or operators
to ensure the toolkit is set up correctly.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import json
import logging
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.logger import setup_logger
from helpers.output import print_error, print_success, print_info, ui_header, print_blank

log = logging.getLogger(__name__)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "src", "python", "config", "config.json")

def check_config():
    """Checks for the existence and validity of the main config file."""
    print_info(f"Checking for config file at: {CONFIG_PATH}")
    log.info("Checking for config file at: %s", CONFIG_PATH)

    if not os.path.exists(CONFIG_PATH):
        print_error("Config file not found.")
        log.error("Config file not found at expected path.")
        return False

    with open(CONFIG_PATH, "r") as f:
        try:
            config = json.load(f)
            print_success("Config file found and is valid JSON.")
            log.info("Config file loaded successfully.")
            return config
        except json.JSONDecodeError:
            print_error("Config file is not valid JSON.")
            log.error("Config file could not be parsed due to JSONDecodeError.")
            return False

def check_directories(config):
    """Checks for the existence of directories specified in the config."""
    if not config:
        return False

    log_dir = os.path.join(PROJECT_ROOT, "src", "python", "logs")

    relative_capture_path = config.get("paths", {}).get("capture_directory", "output/captures")
    python_base_dir = os.path.join(PROJECT_ROOT, "src", "python")
    capture_dir = os.path.abspath(os.path.join(python_base_dir, relative_capture_path))

    print_info(f"Checking for log directory: {log_dir}")
    log.info("Checking for log directory: %s", log_dir)
    if not os.path.isdir(log_dir):
        print_error("Log directory does not exist.")
        log.error("Log directory not found.")
        return False
    print_success("Log directory found.")

    print_info(f"Checking for capture directory: {capture_dir}")
    log.info("Checking for capture directory: %s", capture_dir)
    if not os.path.isdir(capture_dir):
        print_error("Capture directory does not exist.")
        log.error("Capture directory not found.")
        return False
    print_success("Capture directory found.")

    return True

def main():
    """Runs all diagnostic checks and prints a final summary."""
    setup_logger("diagnostic")
    ui_header("WSTT Environment Diagnostic Check")
    print_blank()

    config = check_config()
    dirs_ok = check_directories(config)

    print_blank()
    if config and dirs_ok:
        print_success("✅ All checks passed. Environment appears to be configured correctly.")
    else:
        print_error("❌ One or more checks failed. Please review the output above.")
        sys.exit(1) # Exit with a non-zero code to indicate failure

if __name__ == "__main__":
    main()