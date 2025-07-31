#!/usr/bin/env python3
"""t006.py

Detection script for T006 - Misconfigured Access Point.

This script orchestrates the detection of misconfigured access points by
identifying inconsistencies in the beacon frames of APs that share the same
SSID. It leverages the central analysis engine to find these anomalies, which
can indicate either a simple misconfiguration or a potential rogue AP.

Author:      Paul Smurthwaite
Date:        2025-05-17
Module:      TM470-25B
"""

# ─── External Modules  ───
import logging
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.analysis import analyse_capture, detect_misconfigured_aps_context
from helpers.logger import setup_logger
from helpers.output import (
    ui_clear_screen,
    ui_header,
    print_blank,
    print_waiting,
    print_success,
    print_error,
    print_warning,
    print_prompt,
    print_info,
    print_none,
)
from helpers.parser import select_capture_file
from helpers.theme import *

log = logging.getLogger(__name__)


def print_table(title, data, headers="keys"):
    """Prints a formatted table to the console if data is present."""
    if data:
        print_info(title)
        print(tabulate(data, headers=headers, tablefmt="outline"))
        print_blank()


def main():
    """
    Orchestrates the T006 Misconfigured AP detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify misconfigured access points based on their security posture.
    """
    setup_logger("t006")
    log.info("T006 Misconfigured AP detection script started.")

    ui_clear_screen()
    ui_header("T006 – Misconfigured Access Point")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    context = analyse_capture(cap)
    log.info("Analysis complete. Context created with %d APs.", len(context['access_points']))
    print_success("Analysis context created successfully.")

    print_waiting("Detecting misconfigured access points...")
    misconfigured_aps = detect_misconfigured_aps_context(context)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No critically or seriously misconfigured APs were detected."
    observations = ["All detected access points appear to be using modern, strong encryption (WPA2/WPA3)."]
    
    if misconfigured_aps:
        status = "POSITIVE"
        conclusion = "One or more access points with weak or no encryption were detected."
        observations = [
            "APs using Open, WEP, or legacy WPA1 configurations were found.",
            "These networks are vulnerable to eavesdropping and other attacks."
        ]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T006 – Misconfigured Access Point - Summary")
    print_blank()

    # Define the exact order and headers for the final table
    display_headers = ["SSID", "BSSID", "Reason"]
    display_data = [[ap.get(h.lower(), 'N/A') for h in display_headers] for ap in misconfigured_aps]
    coloured_headers = [colour(h, "bold") for h in display_headers]
    print_table("Misconfigured Access Points Detected:", display_data, headers=coloured_headers)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    print_success(f"Detection Result: {status}") if status == "NEGATIVE" else print_error(f"Detection Result: {status}")
    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()