#!/usr/bin/env python3
"""t001.py

Detection script for T001 - Unencrypted Traffic.

This script orchestrates the detection of unencrypted traffic over open
wireless networks. It leverages the central analysis engine to identify all
access points and data flows, then applies specific logic to find clients
communicating over non-WPA networks.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules ───
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
    Orchestrates the T001 Unencrypted Traffic detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify unencrypted data flows. It concludes by presenting a detailed
    summary and a final verdict.
    """
    setup_logger("t001")
    log.info("T001 Unencrypted Traffic detection script started.")

    ui_clear_screen()
    ui_header("T001 – Unencrypted Traffic Detection")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        print_error("Capture object was not returned.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    log.info("Calling the analysis engine.")
    context = analyse_capture(cap)
    log.info(
        "Analysis complete. Context created with %d APs and %d data frames.",
        len(context['access_points']),
        len(context['data_traffic'])
    )
    print_success("Analysis context created successfully.")

    print_waiting("Detecting unencrypted traffic flows...")
    all_aps = list(context['access_points'].values())
    open_aps = [ap for ap in all_aps if not ap.get('privacy')]
    unencrypted_flows = detect_unencrypted_traffic_context(context)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No evidence of unencrypted traffic over an open network was found."
    observations = ["The network environment appears secure from this threat."]
    
    if unencrypted_flows:
        status = "POSITIVE"
        conclusion = "Unencrypted client communication over an open wireless network was observed."
        observations = ["An open (unencrypted) AP was detected.", "A client was observed exchanging readable data over this network."]
    elif open_aps:
        status = "PARTIAL"
        conclusion = "An open (unencrypted) wireless network was detected, but no clients were observed using it."
        observations = ["An open AP was detected, posing a potential risk.", "No client traffic was captured on the open network."]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T001 – Unencrypted Traffic Detection - Summary")
    print_blank()

    print_table("Access Points:", all_aps)
    print_table("Unencrypted Flows:", unencrypted_flows)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    if status == "POSITIVE":
        print_error("Detection Result: POSITIVE")
    elif status == "NEGATIVE":
        print_success("Detection Result: NEGATIVE")
    else:
        print_warning("Detection Result: PARTIAL")

    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()