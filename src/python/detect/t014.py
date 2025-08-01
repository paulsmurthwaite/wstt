#!/usr/bin/env python3
"""t014.py

Detection script for T014 - ARP Spoofing.

This script orchestrates the detection of ARP spoofing (or ARP cache
poisoning) attacks. It leverages the central analysis engine to identify
contradictory ARP replies, where a single IP address is claimed by multiple
MAC addresses, which is a definitive indicator of a man-in-the-middle attack.

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
from helpers.analysis import analyse_capture, detect_arp_spoofing_context
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
    Orchestrates the T014 ARP Spoofing detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify ARP cache poisoning events.
    """
    setup_logger("t014")
    log.info("T014 ARP Spoofing detection script started.")

    ui_clear_screen()
    ui_header("T014 – ARP Spoofing")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    context = analyse_capture(cap)
    log.info("Analysis complete. Context created with %d ARP frames.", len(context['arp_frames']))
    print_success("Analysis context created successfully.")

    print_waiting("Detecting ARP spoofing events...")
    spoof_events = detect_arp_spoofing_context(context)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No ARP spoofing activity was detected."
    observations = ["No contradictory ARP replies were found in the capture."]
    
    if spoof_events:
        status = "POSITIVE"
        conclusion = "An ARP spoofing attack was detected."
        observations = [
            "Contradictory ARP replies were observed, indicating an attempt to poison the ARP cache of network devices.",
            "This is a strong indicator of an active man-in-the-middle (MitM) attack."
        ]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T014 – ARP Spoofing - Summary")
    print_blank()

    print_table("ARP Spoofing Events Detected:", spoof_events)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    print_success(f"Detection Result: {status}") if status == "NEGATIVE" else print_error(f"Detection Result: {status}")
    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()