#!/usr/bin/env python3
"""preflight.py

Performs all pre-flight environmental checks to ensure WSTT can run.

This module is designed to be called at the very start of the application's
lifecycle. It verifies root privileges, checks for essential system
dependencies, and ensures a wireless interface is available, preventing
crashes and providing clear, actionable error messages to the user.

Author:      Paul Smurthwaite
Date:        2025-05-17
Module:      TM470-25B
"""

import os
import json
import shutil

from helpers.output import print_error, print_info, print_action, print_blank, print_success
from helpers.system import get_current_interface

# A dictionary mapping essential command-line tools to the package that provides them.
ESSENTIAL_DEPS = {
    "airodump-ng": "aircrack-ng",
    "tcpdump": "tcpdump",
    "iw": "iw",
}

# A dictionary mapping essential Python packages to their PyPI install names.
PYTHON_DEPS = {
    "scapy": "scapy",
    "pyfiglet": "pyfiglet",
    "tabulate": "tabulate",
}

# Define a single source of truth for the project's root directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

BASH_CONFIG_DIR = os.path.join(PROJECT_ROOT, "src", "bash", "config")
GLOBAL_CONF_PATH = os.path.join(BASH_CONFIG_DIR, "global.conf")
PYTHON_CONFIG_DIR = os.path.join(PROJECT_ROOT, "src", "python", "config")
PYTHON_CONF_PATH = os.path.join(PYTHON_CONFIG_DIR, "config.json")

def _check_config_files():
    """Verify that essential configuration files exist."""
    print_info("Checking for Bash config (global.conf)...")
    if not os.path.exists(GLOBAL_CONF_PATH):
        print_error(f"Configuration file not found: global.conf")
        print_action(f"Expected at: {GLOBAL_CONF_PATH}")
        return False

    print_info("Checking for Python config (config.json)...")
    if not os.path.exists(PYTHON_CONF_PATH):
        print_error(f"Configuration file not found: config.json")
        print_action(f"Expected at: {PYTHON_CONF_PATH}")
        return False

    return True

def _check_output_directories():
    """
    Verifies that essential output directories exist, creating them if necessary.

    This function checks for the log, scan, and capture directories based on the
    project's standard structure and creates them if they are missing.
    """
    print_info("Checking output directories...")
    try:
        # Define directories based on the project's standard structure
        log_dir = os.path.join(PROJECT_ROOT, "src", "python", "logs")
        scan_dir = os.path.join(PROJECT_ROOT, "src", "output", "scans")
        capture_dir = os.path.join(PROJECT_ROOT, "src", "output", "captures")

        for name, path in {"Log": log_dir, "Scan": scan_dir, "Capture": capture_dir}.items():
            if not os.path.isdir(path):
                print_action(f"{name} directory not found. Attempting to create it...")
                try:
                    os.makedirs(path, exist_ok=True)
                    print_success(f"Successfully created directory: {path}")
                except OSError as e:
                    print_error(f"Failed to create directory: {path}")
                    print_action(f"Error: {e}. Please check permissions.")
                    return False
        return True

    except Exception as e:
        print_error(f"An unexpected error occurred while checking directories: {e}")
        return False

def _check_root():
    """Verify the script is running with root privileges."""
    if os.geteuid() != 0:
        print_error("This toolkit requires root privileges to manage network interfaces.")
        print_action("Please run the script using 'sudo'.")
        return False
    return True

def _check_dependencies():
    """Verify that all essential command-line tools are installed."""
    all_deps_found = True
    for tool, package in ESSENTIAL_DEPS.items():
        if not shutil.which(tool):
            print_error(f"Dependency Check Failed: '{tool}' not found.")
            print_action(f"Please install the '{package}' package (e.g., 'sudo apt install {package}').")
            all_deps_found = False
    return all_deps_found

def _check_python_dependencies():
    """Verify that all essential Python packages are installed."""
    print_info("Checking for Python dependencies...")
    all_deps_found = True
    for package_name, install_name in PYTHON_DEPS.items():
        try:
            # Use __import__ to check for module existence by its string name
            __import__(package_name)
        except ImportError:
            print_error(f"Python package '{package_name}' not found in the current environment.")
            print_action(f"Please install it using: 'sudo pip install {install_name}'")
            all_deps_found = False
    return all_deps_found

def _check_wireless_interface():
    """Verify that a usable wireless interface is available."""
    interface = get_current_interface()
    # The helper returns an error string if it fails to find the interface
    if "[!]" in interface or "?" in interface:
        print_error("No wireless interface found or configured in 'src/bash/config/global.conf'.")
        print_action("Please ensure a wireless adapter is connected and correctly configured.")
        return False
    return True

def run_preflight_checks():
    """
    Run all pre-flight environmental checks.

    Returns:
        bool: True if all checks pass, False otherwise.
    """
    print_info("Running pre-flight environment checks...")
    print_blank()

    # Chain checks together; if one fails, the rest won't run.
    if not (_check_root() and _check_dependencies() and _check_python_dependencies() and _check_config_files() and _check_output_directories() and _check_wireless_interface()):
        print_blank()
        print_error("Environment checks failed. Please resolve the issues above and restart.")
        return False

    print_info("All pre-flight checks passed.")
    print_blank()
    return True
