#!/usr/bin/env python3
"""t007.py

Detection script for T007 - Deauthentication Flood.

This script orchestrates the detection of deauthentication flood attacks by
analysing the rate of deauth/disassoc frames in a packet capture. It
leverages the central analysis engine to identify high-volume bursts of these
frames directed at a specific target, which is a clear indicator of a
denial-of-service attack.

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
from helpers.analysis import analyse_capture, detect_deauth_flood_context
from helpers.logger import setup_logger
from helpers.output import (
    ui_clear_screen,
    ui_header,
    print_blank,
    print_waiting,
    print_success,
    print_error,
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
    Orchestrates the T007 Deauthentication Flood detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify deauthentication flood events based on frame velocity.
    """
    setup_logger("t007")
    log.info("T007 Deauthentication Flood detection script started.")

    ui_clear_screen()
    ui_header("T007 – Deauthentication Flood")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    context = analyse_capture(cap)
    log.info("Analysis complete. Context created with %d deauth/disassoc frames.", len(context['deauth_frames']))
    print_success("Analysis context created successfully.")

    print_waiting("Detecting deauthentication flood events...")
    # A threshold of 20 frames/sec is a conservative value for a flood.
    flood_events = detect_deauth_flood_context(context, threshold=20)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No deauthentication flood activity was detected."
    observations = ["The volume of deauthentication and disassociation frames is within normal operational parameters."]
    
    if flood_events:
        status = "POSITIVE"
        conclusion = "A deauthentication flood attack was detected."
        observations = [
            "An abnormally high volume of deauthentication/disassociation frames was sent to a target in a short time.",
            "This indicates a deliberate denial-of-service attack intended to disconnect clients from the network."
        ]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T007 – Deauthentication Flood - Summary")
    print_blank()

    print_table("Deauthentication Flood Events Detected:", flood_events)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    print_success(f"Detection Result: {status}") if status == "NEGATIVE" else print_error(f"Detection Result: {status}")
    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()