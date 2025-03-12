#!/usr/bin/env python3
"""wstt_interface.py

Wireless interface unified mode control, reset, and status

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import argparse
import logging
import subprocess
import sys
from wstt_utils import check_dependencies, check_interface_exists, get_interface_mode, reset_interface, bring_interface_down, bring_interface_up, GREEN, RED, YELLOW, RESET

def enable_mode(interface, mode):
    """Enable the specified mode (managed/monitor) on the wireless interface."""
    if mode not in ["managed", "monitor"]:
        msg = f"Invalid mode '{mode}'. Choose 'managed' or 'monitor'."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

    if not check_interface_exists(interface):
        msg = f"Interface {interface} not found."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

    current_mode = get_interface_mode(interface)
    if current_mode == mode:
        msg = f"{interface} is set to {mode.capitalize()} mode."
        print(f"{YELLOW}[INFO] {msg}{RESET}")
        logging.info(msg)
        sys.exit(0)

    try:
        bring_interface_down(interface)  # Ensure interface is down before mode change
        subprocess.run(["sudo", "iw", interface, "set", "type", mode], check=True)  # Apply mode change
        print(f"{YELLOW}[INFO] Changing {interface} to {mode.capitalize()} mode...{RESET}")
        logging.info(f"Mode changed to {mode.capitalize()} for {interface}.")
        bring_interface_up(interface)  # Bring interface back up after mode change

        new_mode = get_interface_mode(interface)
        msg = f"{interface} is set to {mode.capitalize()} mode." if new_mode == mode else f"Failed to enable {mode} mode on {interface}."
        
        color = GREEN if new_mode == mode else RED
        log_level = logging.info if new_mode == mode else logging.error

        print(f"{color}[{'SUCCESS' if new_mode == mode else 'ERROR'}] {msg}{RESET}")
        log_level(msg)

        if new_mode != mode:
            sys.exit(1)

    except subprocess.CalledProcessError:
        msg = "Command execution failed."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

def check_status(interface):
    """Check and display the current mode of the specified interface."""
    if not check_interface_exists(interface):
        msg = f"Interface {interface} not found."
        print(f"{RED}[ERROR] {msg}{RESET}")
        logging.error(msg)
        sys.exit(1)

    mode = get_interface_mode(interface)
    msg = f"{interface} is currently set to {mode.capitalize()} mode." if mode else f"Unable to determine mode for {interface}."

    color = GREEN if mode else RED
    log_level = logging.info if mode else logging.error

    print(f"{color}[{'INFO' if mode else 'ERROR'}] {msg}{RESET}")
    log_level(msg)

    if not mode:
        sys.exit(1)

if __name__ == "__main__":
    check_dependencies()  # Ensure required tools exist

    parser = argparse.ArgumentParser(description="Wireless Security Testing Toolkit (WSTT) Mode Control")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to operate on")
    parser.add_argument("-m", "--mode", choices=["managed", "monitor"], help="Specify the required mode")
    parser.add_argument("-r", "--reset", action="store_true", help="Reset the interface")
    parser.add_argument("-s", "--status", action="store_true", help="Check the current mode of the interface")

    args = parser.parse_args()

    if args.mode:
        enable_mode(args.interface, args.mode)
    elif args.reset:
        reset_interface(args.interface)  # Reset interface without mode change
    elif args.status:
        check_status(args.interface)
    else:
        print(f"{RED}[ERROR] No valid action provided. Use -m <mode>, -r, or -s.{RESET}")
        sys.exit(1)
