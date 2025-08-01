#!/usr/bin/env python3
"""t008.py

Detection script for T008 - Beacon Flood.

This script orchestrates the detection of beacon flood attacks by analysing
the volume and variety of beacon frames in a packet capture. It leverages the
central analysis engine to identify an abnormally high rate of beacons or an
unusually large number of unique BSSIDs, which are clear indicators of a
denial-of-service or network scanning disruption attack.

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
from helpers.analysis import analyse_capture, detect_beacon_flood_context
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
    Orchestrates the T008 Beacon Flood detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine, and then applies specific detection logic to
    identify beacon flood events based on frame volume and variety.
    """
    setup_logger("t008")
    log.info("T008 Beacon Flood detection script started.")

    ui_clear_screen()
    ui_header("T008 – Beacon Flood")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    context = analyse_capture(cap)
    log.info("Analysis complete. Context created with %d beacon frames.", len(context['beacon_frames']))
    print_success("Analysis context created successfully.")

    print_waiting("Detecting beacon flood events...")
    flood_events = detect_beacon_flood_context(context, volume_threshold=100, variety_threshold=20)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No beacon flood activity was detected."
    observations = ["The volume and variety of beacon frames are within normal operational parameters."]
    
    if flood_events:
        status = "POSITIVE"
        conclusion = "A beacon flood attack was detected."
        observations = [
            "An abnormally high volume or variety of beacon frames was detected in a short time.",
            "This indicates a deliberate attack intended to disrupt network discovery or overwhelm client devices."
        ]
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T008 – Beacon Flood - Summary")
    print_blank()

    print_table("Beacon Flood Events Detected:", flood_events)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    print_success(f"Detection Result: {status}") if status == "NEGATIVE" else print_error(f"Detection Result: {status}")
    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()