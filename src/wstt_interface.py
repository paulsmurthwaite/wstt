#!/usr/bin/env python3
"""wstt_interface.py

Wireless interface unified mode control, reset, and status

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import argparse
import sys
from wstt_utils import (
    check_dependencies,
    reset_interface,
    enable_mode,
    check_status
)

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
        print("[ERROR] No valid action provided. Use -m <mode>, -r, or -s.")
        sys.exit(1)
