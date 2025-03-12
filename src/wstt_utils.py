#!/usr/bin/env python3
"""wstt_utils.py

Utility module for common wireless interface operations, including:
- Checking interface existence
- Retrieving interface mode
- Managing interface state (down/up)
- Resetting interfaces
- Logging system events

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import logging
import subprocess
import shutil
import sys
import time

# ANSI escape codes for text decoration (used for terminal colour output)
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Configure logging to log events and errors
logging.basicConfig(
    filename="wstt.log",  # Log file
    level=logging.DEBUG,  # Capture all log levels
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

def check_dependencies():
    """Ensure required tools (ip, iw) are installed before running."""
    missing = [cmd for cmd in ["ip", "iw"] if shutil.which(cmd) is None]
    if missing:
        msg = f"Missing required command(s): {', '.join(missing)}. Install them and retry."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)  # Logs error
        sys.exit(1)

def check_interface_exists(interface):
    """Check if the specified wireless interface exists."""
    result = subprocess.run(["ip", "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0  # Returns True if the interface exists

def get_interface_mode(interface):
    """Retrieve the current mode of the specified wireless interface."""
    try:
        result = subprocess.run(["iw", interface, "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.split("\n"):
            if "type" in line:
                return line.split()[-1].strip()  # Extract and return the mode
    except Exception:
        return None  # Return None if mode cannot be determined
    
    return None

def bring_interface_down(interface):
    """Bring the wireless interface down to allow mode changes."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        print(f"{YELLOW}[INFO] Interface {interface} is now down.{RESET}")
        logging.info(f"Interface {interface} is now down.")
    except subprocess.CalledProcessError:
        msg = f"Failed to bring interface {interface} down."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

def bring_interface_up(interface):
    """Bring the wireless interface back up after mode changes."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        print(f"{YELLOW}[INFO] Interface {interface} is now up.{RESET}")
        logging.info(f"Interface {interface} is now up.")
    except subprocess.CalledProcessError:
        msg = f"Failed to bring interface {interface} up."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

def reset_interface(interface):
    """Reset the wireless interface by bringing it down and back up."""
    try:
        bring_interface_down(interface)  # Ensure interface is down
        time.sleep(0.5)  # Allow short delay for stability
        bring_interface_up(interface)  # Bring interface back up

        # Verify interface is back online
        result = subprocess.run(["ip", "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            msg = f"Interface {interface} has been reset."
            print(f"{YELLOW}[INFO] {msg}{RESET}")
            logging.info(msg)
        else:
            msg = f"Interface {interface} did not come back online."
            print(f"{RED}[ERROR] {msg}{RESET}")
            logging.error(msg)
            sys.exit(1)

    except subprocess.CalledProcessError:
        msg = f"Failed to reset interface {interface}."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)
