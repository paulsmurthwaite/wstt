#!/usr/bin/env python3
"""t002.py

Detection script for T002: Probe Request Snooping.

This script analyses a packet capture file to identify and report on all 802.11
Probe Request frames. It extracts the source MAC address and the requested SSID
from each probe, providing insight into which devices are searching for which
networks. This is a key indicator of passive reconnaissance.

Author:      Paul Smurthwaite
Date:        2025-05-17
Module:      TM470-25B
"""

# ─── External Modules  ───
import os
import sys
import logging
from collections import defaultdict
from scapy.all import Dot11ProbeReq
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
)
from helpers.theme import colour
from helpers.output import print_none

log = logging.getLogger(__name__)

def print_table(title, data, headers):
    """Prints a formatted table to the console if data is present."""
    if data:
        print_info(title)
        print(tabulate(data, headers=headers, tablefmt="outline"))
        print_blank()

def main():
    """Main function to run the T002 detection script."""
    setup_logger("t002")
    log.info("T002 Probe Request Snooping detection script started.")

    try:
        ui_clear_screen()
        ui_header("T002 – Probe Request Snooping")
        print_blank()

        filepath, packets = select_capture_file(load=True)

        if not packets:
            log.error("No capture file was selected or loaded. Aborting.")
            return

        print_blank()
        log.info("Selected capture file: %s", filepath)
        print_action("Running single-pass analysis engine...")
        context = analyse_capture(packets)
        log.info(
            "Analysis complete. Context created with %d APs and %d probe requests.",
            len(context['access_points']),
            sum(len(ssids) for ssids in context['probe_requests'].values())
        )
        print_success("Analysis context created successfully.")

        # Retrieve probe request data from the central analysis context
        probes_by_mac = context.get("probe_requests", {})

        # --- Evaluation ---
        status = "NEGATIVE"
        conclusion = "No Probe Requests were found in the capture file."
        observations = ["No devices were observed probing for wireless networks."]

        if probes_by_mac:
            status = "POSITIVE"
            conclusion = "Probe Requests were detected, indicating devices are searching for known networks."
            observations = [
                "Client devices were observed broadcasting the names of networks they have previously connected to.",
                "This information can be used by an attacker for reconnaissance or to set up an Evil Twin attack."
            ]
            # Find the device that probed for the most unique SSIDs
            if probes_by_mac:
                most_active_device = max(probes_by_mac, key=lambda k: len(probes_by_mac[k]))
                num_ssids = len(probes_by_mac[most_active_device])
                observations.append(f"The most active device ({most_active_device}) exposed {num_ssids} unique network names.")
            log.info("Found %d devices sending probe requests.", len(probes_by_mac))
        else:
            log.info("No Probe Requests found in the capture file.")

        print_blank()
        print_prompt("Press Enter to display the summary")
        input()
        ui_clear_screen()
        ui_header("T002 – Probe Request Snooping - Summary")
        print_blank()

        # --- Build Device-Centric Summary Table ---
        headers = [colour("Source MAC", "bold"), colour("Unique SSID Count", "bold"), colour("Exposed SSIDs", "bold")]
        table_data = []

        # Sort devices by the number of unique SSIDs they probed for
        sorted_probes = sorted(probes_by_mac.items(), key=lambda item: len(item[1]), reverse=True)

        for mac, ssids in sorted_probes:
            ssid_list_str = "\n".join(sorted(list(ssids)))
            table_data.append([mac, len(ssids), ssid_list_str])

        print_table("Probe Request Emitters:", table_data, headers=headers)

        print_info("Observations:")
        for line in observations:
            print_none(f"- {line}")
        print_blank()

        if status == "POSITIVE":
            print_error(f"Detection Result: {status}")
        else:
            print_success(f"Detection Result: {status}")

        print_none(f"- {conclusion}")
        log.info("Final Verdict: %s. Conclusion: %s", status, conclusion)

    except Exception as e:
        log.error("An unexpected error occurred: %s", e, exc_info=True)
        print_error(f"An unexpected error occurred: {e}")
        print_action("Please check the log file for more details.")

if __name__ == "__main__":
    main()