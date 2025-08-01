#!/usr/bin/env python3
"""t015.py

Detection script for T015 - Malicious Hotspot Auto-Connect.

This script orchestrates the detection of a malicious hotspot by identifying
unencrypted traffic over an open wireless network. It leverages the central
analysis engine to find open APs and clients communicating over them, then
frames the findings in the context of an attacker exploiting a device's
auto-connect feature to establish a man-in-the-middle position.

Author:      Paul Smurthwaite
Date:        2025-05-18
Module:      TM470-25B
"""

# ─── External Modules  ───
import logging
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.analysis import analyse_capture, detect_unencrypted_traffic_context
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
    Orchestrates the T015 Malicious Hotspot detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify unencrypted data flows, interpreting them as evidence of a
    successful malicious hotspot attack.
    """
    setup_logger("t015")
    log.info("T015 Malicious Hotspot detection script started.")

    ui_clear_screen()
    ui_header("T015 – Malicious Hotspot Auto-Connect")
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

    print_waiting("Detecting unencrypted traffic flows...")
    all_aps = list(context['access_points'].values())
    open_aps = [ap for ap in all_aps if not ap.get('privacy')]
    unencrypted_flows = detect_unencrypted_traffic_context(context)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No evidence of a malicious hotspot attack was found."
    observations = ["No open wireless networks were detected in the capture."]
    
    if unencrypted_flows:
        status = "POSITIVE"
        conclusion = "A client auto-connected to a malicious hotspot and is leaking unencrypted data."
        observations = [
            "An open AP impersonating a public hotspot was detected.",
            "A client was observed exchanging readable data, confirming a successful MitM position via auto-connect."
        ]
    elif open_aps:
        status = "PARTIAL"
        conclusion = "A potential malicious hotspot was detected, but no clients were observed connecting to it."
        observations = [
            "An open AP impersonating a public hotspot was detected, posing a risk.",
            "This could be an inactive honeypot waiting for a victim."
        ]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T015 – Malicious Hotspot - Summary")
    print_blank()

    print_table("Open Access Points Detected:", open_aps)
    print_table("Unencrypted Client Flows:", unencrypted_flows)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    if status == "POSITIVE": print_error("Detection Result: POSITIVE")
    elif status == "NEGATIVE": print_success("Detection Result: NEGATIVE")
    else: print_warning("Detection Result: PARTIAL")

    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()