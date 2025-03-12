#!/usr/bin/env python3
# Check wireless interface status

import argparse
import logging
import subprocess
import sys
from wstt_utils import check_dependencies, check_interface_exists, get_interface_mode, GREEN, RED, YELLOW, RESET
    
def check_status(interface):
    """ Check and display the current mode of the specified interface. """
    check_dependencies()  # Ensure required tools are installed before proceeding

    if not check_interface_exists(interface):
        msg = f"Interface {interface} not found."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

    mode = get_interface_mode(interface)
    if mode:
        msg = f"{interface} is currently in {mode.capitalize()} mode."
        print(f"{GREEN}[INFO] {msg}{RESET}")
        logging.info(msg)
    else:
        msg = f"Unable to determine mode for {interface}."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the current mode of a wireless interface.")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to check mode")
    args = parser.parse_args()

    check_status(args.interface)
