#!/usr/bin/env python3
"""wstt_utils.py

Utility module for common wireless interface operations, including:
- Checking interface existence
- Checking interface status
- Retrieving interface mode
- Managing interface state (down/up)
- Resetting interfaces
- Enabling monitor/managed modes
- Logging system events

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import logging
import os
import subprocess
import shutil
import sys
import time

# Define log directory and file
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)  # Create logs/ if missing

log_file = os.path.join(log_dir, "wstt.log")  # Unified log file for all scripts

# Configure logging
logger = logging.getLogger("wstt")
logger.setLevel(logging.INFO)

if not logger.hasHandlers():
    log_handler = logging.FileHandler(log_file)
    log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(log_handler)

def check_dependencies():
    """Ensure required tools (ip, iw) are installed before running."""
    missing = [cmd for cmd in ["ip", "iw"] if shutil.which(cmd) is None]
    if missing:
        msg = f"Missing required command(s): {', '.join(missing)}. Install them and retry."
        logger.error(msg)
        sys.exit(1)

def check_interface_exists(interface):
    """Check if the specified wireless interface exists."""
    result = subprocess.run(["ip", "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def check_status(interface):
    """Check and display the current mode of the specified interface."""
    if not check_interface_exists(interface):
        logger.error(f"Interface {interface} not found.")
        sys.exit(1)
    
    mode = get_interface_mode(interface)
    if mode:
        logger.info(f"{interface} is currently set to {mode.capitalize()} mode.")
    else:
        logger.error(f"Unable to determine mode for {interface}.")
        sys.exit(1)

def get_interface_mode(interface):
    """Retrieve the current mode of the specified wireless interface."""
    try:
        result = subprocess.run(["iw", interface, "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.split("\n"):
            if "type" in line:
                return line.split()[-1].strip()
    except Exception:
        return None
    
    return None

def bring_interface_down(interface):
    """Bring the wireless interface down to allow mode changes."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        logger.info(f"Interface {interface} is now down.")
    except subprocess.CalledProcessError:
        logger.error(f"Failed to bring interface {interface} down.")
        sys.exit(1)

def bring_interface_up(interface):
    """Bring the wireless interface back up after mode changes."""
    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        logger.info(f"Interface {interface} is now up.")
    except subprocess.CalledProcessError:
        logger.error(f"Failed to bring interface {interface} up.")
        sys.exit(1)

def reset_interface(interface):
    """Reset the wireless interface by bringing it down and back up."""
    try:
        bring_interface_down(interface)
        time.sleep(0.5)
        bring_interface_up(interface)
        result = subprocess.run(["ip", "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            logger.info(f"Interface {interface} has been reset.")
        else:
            logger.error(f"Interface {interface} did not come back online.")
            sys.exit(1)
    except subprocess.CalledProcessError:
        logger.error(f"Failed to reset interface {interface}.")
        sys.exit(1)

def enable_mode(interface, mode):
    """Enable the specified mode (managed/monitor) on the wireless interface."""
    if mode not in ["managed", "monitor"]:
        logger.error(f"Invalid mode '{mode}'. Choose 'managed' or 'monitor'.")
        sys.exit(1)
    
    if not check_interface_exists(interface):
        logger.error(f"Interface {interface} not found.")
        sys.exit(1)
    
    current_mode = get_interface_mode(interface)
    if current_mode == mode:
        logger.info(f"{interface} is already in {mode.capitalize()} mode.")
        sys.exit(0)
    
    try:
        bring_interface_down(interface)
        subprocess.run(["sudo", "iw", interface, "set", "type", mode], check=True)
        logger.info(f"Mode changed to {mode.capitalize()} for {interface}.")
        bring_interface_up(interface)
        new_mode = get_interface_mode(interface)
        if new_mode != mode:
            logger.error(f"Failed to enable {mode} mode on {interface}.")
            sys.exit(1)
    except subprocess.CalledProcessError:
        logger.error("Command execution failed.")
        sys.exit(1)

def spinner(stop_event):
    """Display a rotating spinner while a process is running."""
    spin_chars = "|/-\\"
    while not stop_event.is_set():
        for char in spin_chars:
            sys.stdout.write(f"\rScanning... {char} ")
            sys.stdout.flush()
            time.sleep(0.1)
            if stop_event.is_set():
                break
    sys.stdout.write("\rScanning complete!    \n")
    sys.stdout.flush()
