#!/usr/bin/env python3
"""t003.py

Detection script for T003: SSID Harvesting.

This script orchestrates the detection of SSID harvesting by analysing a
packet capture file. It leverages the central analysis engine to identify all
Beacon and Probe Response frames, then presents a consolidated list of all
discovered Access Points and their key characteristics.

Author:      Paul Smurthwaite
Date:        2025-05-17
Module:      TM470-25B
"""

# ─── External Modules  ───
import os
import sys
import logging
from tabulate import tabulate

# Add the project's root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ─── Local Modules ───
from helpers.analysis import analyse_capture
from helpers.parser import select_capture_file
from helpers.logger import setup_logger
from helpers.output import (
    print_action,
    print_prompt,
    ui_clear_screen,
    ui_header,
    print_blank,
    print_error,
    print_info,
    print_success,
    print_none,
)
from helpers.theme import colour

log = logging.getLogger(__name__)

def print_table(title, data, headers):
    """Prints a formatted table to the console if data is present."""
    if data:
        print_info(title)
        print(tabulate(data, headers=headers, tablefmt="outline"))
        print_blank()

def main():
    """Main function to run the T003 detection script."""
    setup_logger("t003")
    log.info("T003 SSID Harvesting detection script started.")

    try:
        ui_clear_screen()
        ui_header("T003 – SSID Harvesting")
        print_blank()

        filepath, packets = select_capture_file(load=True)

        if not packets:
            log.error("No capture file was selected or loaded. Aborting.")
            return

        print_blank()
        log.info("Selected capture file: %s", filepath)
        print_action("Running single-pass analysis engine...")
        context = analyse_capture(packets)
        log.info("Analysis complete. Context created with %d APs.", len(context['access_points']))
        print_success("Analysis context created successfully.")

        # --- Evaluation ---
        all_aps = list(context['access_points'].values())
        status = "NEGATIVE"
        conclusion = "No Beacon or Probe Response frames were found."
        observations = ["No Access Points were observed advertising their presence."]

        if all_aps:
            status = "POSITIVE"
            conclusion = "Access Points were detected broadcasting their SSIDs."
            observations = [
                "Beacon and/or Probe Response frames were captured, revealing the presence of active networks.",
                "This harvested list forms a baseline of legitimate networks in the area."
            ]

        print_blank()
        print_prompt("Press Enter to display the summary")
        input()
        ui_clear_screen()
        ui_header("T003 – SSID Harvesting - Summary")
        print_blank()

        # Define the exact order and headers for the final table
        display_headers = ["SSID", "BSSID", "Channel", "Privacy"]
        display_data = [[ap.get(h.lower(), 'N/A') for h in display_headers] for ap in all_aps]
        coloured_headers = [colour(h, "bold") for h in display_headers]

        print_table("Harvested Access Points:", display_data, headers=coloured_headers)

        print_info("Observations:")
        for line in observations:
            print_none(f"- {line}")
        print_blank()

        print_success(f"Detection Result: {status}")
        print_none(f"- {conclusion}")
        log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

    except Exception as e:
        log.error("An unexpected error occurred: %s", e, exc_info=True)
        print_error(f"An unexpected error occurred: {e}")
        print_action("Please check the log file for more details.")

if __name__ == "__main__":
    main()