#!/usr/bin/env python3
"""t004.py

Detection script for T004 - Evil Twin Attack.

This script orchestrates the detection of Evil Twin attacks by analysing a
packet capture file. It leverages the central analysis engine to build a
comprehensive context of the network traffic, then applies multiple layers
of detection logic to identify SSID collisions, beacon anomalies, and client
re-association events that indicate a potential attack.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.analysis import (
    analyse_capture,
    detect_rogue_aps_context,
    detect_beacon_anomalies_context,
    detect_duplicate_handshakes_context,
    detect_client_traffic_context
)
from helpers.output import (
    setup_file_logging,
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


def print_table(title, data, headers="keys"):
    """Prints a formatted table to the console if data is present.

    This helper function checks if the provided data list is not empty
    before printing a title and a formatted table using the tabulate
    library.

    Args:
        title (str): The title to display above the table.
        data (list): The list of dictionaries or other iterables to
                     be tabulated.
        headers (str): The header format string for the tabulate
                       library (e.g., "keys", "firstrow").
    """
    if data:
        print_info(title)
        print(tabulate(data, headers=headers, tablefmt="outline"))
        print_blank()

def main():
    """
    Orchestrates the T004 Evil Twin detection process.

    This function guides the user through selecting a capture file, runs the
    core analysis engine to build a comprehensive context of the network
    traffic, and then applies specific detection logic to identify evidence
    of an Evil Twin attack. It concludes by presenting a detailed summary
    and a final verdict.
    """
    setup_file_logging("t004")
    ui_clear_screen()
    ui_header("T004 – Evil Twin Detection")
    print_blank()
    print_waiting("Reading capture files")

    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    print_blank()
    print_waiting("Running single-pass analysis engine")
    context = analyse_capture(cap)
    print_success("Analysis context created successfully")

    print_blank()
    print_waiting("Detecting rogue APs (SSID collisions)")
    rogue_aps = detect_rogue_aps_context(context)

    print_waiting("Detecting beacon anomalies")
    beacon_anomalies = detect_beacon_anomalies_context(context)

    print_waiting("Detecting duplicate handshakes")
    attack_chains = detect_duplicate_handshakes_context(context)

    print_waiting("Detecting encrypted client traffic")
    client_traffic = detect_client_traffic_context(context)

    print_success("All detection logic executed")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    ui_header("T004 – Evil Twin Detection - Summary")
    print_blank()

    print_table("Access Points:", list(context['access_points'].values()))
    print_table("Rogue APs (SSID Collisions):", rogue_aps)
    print_table("Beacon Anomalies:", beacon_anomalies)
    print_table("Evil Twin Attack Chains:", attack_chains)
    print_table("EAPOL Handshake Frames:", context['eapol_frames'])
    print_table("Encrypted Client Traffic:", client_traffic)

    has_attack_chain = bool(attack_chains)
    has_traffic_with_rogue = False
    if has_attack_chain and client_traffic:
        rogue_ap_in_chain = attack_chains[0]['rogue_ap']
        has_traffic_with_rogue = any(t['ap'] == rogue_ap_in_chain for t in client_traffic)

    status = "NEGATIVE"
    conclusion = "No evidence of an Evil Twin attack was found."
    observations = ["No indicators of impersonation or client re-association were detected."]

    if has_attack_chain:
        if has_traffic_with_rogue:
            status = "POSITIVE"
            conclusion = "A full Evil Twin attack chain with subsequent traffic was confirmed."
            observations = ["Client re-associated with a rogue AP.", "Encrypted traffic was observed with the rogue AP."]
        else:
            status = "PARTIAL"
            conclusion = "An Evil Twin re-association was found, but no subsequent traffic was confirmed."
            observations = ["Client re-associated with a rogue AP, but no MitM traffic was seen."]
    elif rogue_aps or beacon_anomalies:
        status = "PARTIAL"
        conclusion = "Evidence of AP impersonation was found, but no client was observed being attacked."
        observations = ["SSID collision or beacon anomalies detected, indicating a potential rogue AP."]

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

if __name__ == "__main__":
    main()