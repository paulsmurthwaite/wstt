#!/usr/bin/env python3
"""t001.py

Information

Author:      Paul Smurthwaite
Date:        2025-06-18
Module:      TM470-25B
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from helpers.parser import select_capture_file
from helpers.output import *

def main():
    print_action("Reading capture files")

    # Prompt user to select and load a capture
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    try:
        count = sum(1 for _ in cap)
        print_blank
        print_info(f"Number of packets: {count}")
    except Exception as e:
        print_error(f"Failed to count packets: {str(e)}")
        return

    print_blank()
    print_success("PCAP loaded successfully. Ready for Detection logic.")


if __name__ == "__main__":
    main()