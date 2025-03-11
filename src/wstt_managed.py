#!/usr/bin/env python3
# Enable wireless interface MANAGED mode

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

def enable_managed_mode(interface):
    """ Enable managed mode on the specified wireless interface. """
    if not check_interface_exists(interface):
        print(f"{RED}[ERROR] Interface {interface} not found.{RESET}")
        sys.exit(1)

    current_mode = get_interface_mode(interface)
    if current_mode == "managed":
        print(f"{YELLOW}[INFO] {interface} is already in Managed mode.{RESET}")
        sys.exit(0)

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["sudo", "iw", interface, "set", "type", "managed"], check=True)
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)

        new_mode = get_interface_mode(interface)
        if new_mode == "managed":
            print(f"{GREEN}[SUCCESS] {interface} is now in Managed mode.{RESET}")
        else:
            print(f"{RED}[ERROR] Failed to enable managed mode on {interface}.{RESET}")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print(f"{RED}[ERROR] Command execution failed.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enable managed mode on a wireless interface.")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to enable managed mode on")
    args = parser.parse_args()

    enable_managed_mode(args.interface)
