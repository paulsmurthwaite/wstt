#!/usr/bin/env python3
# Check wireless interface status

import argparse
import subprocess
import sys

# ANSI escape codes for text decoration
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def check_interface_exists(interface):
    """ Check if the specified wireless interface exists. """
    result = subprocess.run(["ip", "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def get_interface_mode(interface):
    """ Retrieve the current mode of the interface. """
    try:
        result = subprocess.run(["iw", interface, "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.split("\n"):
            if "type" in line:
                return line.split()[-1]
    except Exception:
        return None
    
def check_status(interface):
    """ Check and display the current mode of the specified interface. """
    if not check_interface_exists(interface):
        print(f"{RED}[ERROR] Interface {interface} not found.{RESET}")
        sys.exit(1)

    mode = get_interface_mode(interface)
    if mode:
        print(f"{GREEN}[INFO] {interface} is currently in {mode.capitalize()} mode.{RESET}")
    else:
        print(f"{RED}[ERROR] Unable to determine mode for {interface}.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check the current mode of a wireless interface.")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to check mode")
    args = parser.parse_args()

    check_status(args.interface)
