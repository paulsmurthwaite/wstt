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

from helpers.ap_analysis import parse_ap_frames
from helpers.parser import select_capture_file
from helpers.output import *
from helpers.theme import *

def main():
    ui_clear_screen()
    ui_header("T001 – Unencrypted Traffic Capture")
    print_blank()
    print_action("Reading capture files")

    # ─── Load Capture ───
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    print_action("Parsing for Access Points")
    access_points = parse_ap_frames(cap)

    if not access_points:
        print_warning("No Access Points found in capture.")
    else:
        for ap in access_points:
            ssid = ap.get("ssid", "<unknown>")
            bssid = ap.get("bssid", "<unknown>")
            privacy = ap.get("privacy", "?")
            rsn = ap.get("rsn", "?")
            print_info(f"Found SSID: '{ssid}' | BSSID: {bssid} | Privacy: {privacy} | RSN: {rsn}")
            if not privacy and not rsn:
                print_success(f"Open network detected: {ssid} ({bssid})")

    print_blank()
    print_info("AP parsing complete. Next: client association analysis.")

if __name__ == "__main__":
    main()