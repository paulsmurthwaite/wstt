#!/usr/bin/env python3
# Enable wireless interface managed mode

import argparse
import logging
import subprocess
import sys
from wstt_utils import check_dependencies, check_interface_exists, get_interface_mode, reset_interface, GREEN, RED, YELLOW, RESET

def enable_managed_mode(interface):
    """ Enable managed mode on the specified wireless interface. """
    check_dependencies()  # Ensure required tools are installed before proceeding

    if not check_interface_exists(interface):
        msg = f"Interface {interface} not found."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

    reset_interface(interface)

    current_mode = get_interface_mode(interface)
    if current_mode == "managed":
        msg = f"{interface} is already in Managed mode."
        print(f"{YELLOW}[INFO] {msg}{RESET}")
        logging.info(msg)
        sys.exit(0)

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

        new_mode = get_interface_mode(interface)
        if new_mode == "managed":
            msg = f"{interface} is now in Managed mode."
            print(f"{GREEN}[SUCCESS] {msg}{RESET}")
            logging.info(msg)
        else:
            msg = f"Failed to enable managed mode on {interface}."
            print(f"{RED}[ERROR] {msg}{RESET}")
            logging.error(msg)
            sys.exit(1)
    except subprocess.CalledProcessError:
        msg = "Command execution failed."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enable managed mode on a wireless interface.")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to enable managed mode on")
    args = parser.parse_args()

    enable_managed_mode(args.interface)
