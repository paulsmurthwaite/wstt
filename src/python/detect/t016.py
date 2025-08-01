#!/usr/bin/env python3
"""t016.py

Detection script for T016 - Directed Probe Response.

This script orchestrates the detection of directed probe response attacks. It
leverages the central analysis engine to correlate probe requests from clients
with probe responses from APs. It flags responses as suspicious if they
originate from a non-beaconing AP, which is a strong indicator of a tool like
airbase-ng being used to impersonate a network.

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
from helpers.analysis import analyse_capture, detect_directed_probe_response_context
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
    Orchestrates the T016 Directed Probe Response detection process.
    """
    setup_logger("t016")
    log.info("T016 Directed Probe Response detection script started.")

    ui_clear_screen()
    ui_header("T016 – Directed Probe Response")
    print_blank()

    path, cap = select_capture_file(load=True)
    if cap is None:
        log.error("No capture file was selected or loaded. Aborting.")
        return
    log.info("Selected capture file: %s", path)

    print_blank()
    print_waiting("Running single-pass analysis engine...")
    context = analyse_capture(cap)
    log.info("Analysis complete. Context created with %d probe requests and %d probe responses.", len(context['probe_requests']), len(context['probe_responses']))
    print_success("Analysis context created successfully.")

    print_waiting("Detecting directed probe response events...")
    probe_events = detect_directed_probe_response_context(context)

    # --- Evaluation ---
    status = "NEGATIVE"
    conclusion = "No correlated probe request/response events were detected."
    observations = ["No clients were observed probing for specific networks that were then answered by an AP."]
    
    if probe_events:
        status = "POSITIVE"
        conclusion = "Correlated probe request/response events were detected."
        observations = [
            "One or more clients sent a probe for a specific network, and an AP responded.",
            "Review the 'Notes' column to assess the legitimacy of the responding APs."
        ]
        # Add a specific observation if a high-confidence event is found
        if any("Standard" not in e["notes"] for e in probe_events):
            observations.append("At least one event has suspicious characteristics (non-beaconing or Evil Twin).")
    
    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T016 – Directed Probe Response - Summary")
    print_blank()

    print_table("Correlated Probe Events:", probe_events)

    print_info("Observations:")
    for line in observations:
        print_none(f"- {line}")
    print_blank()

    print_success(f"Detection Result: {status}") if status == "NEGATIVE" else print_error(f"Detection Result: {status}")
    print_none(f"- {conclusion}")
    log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

if __name__ == "__main__":
    main()