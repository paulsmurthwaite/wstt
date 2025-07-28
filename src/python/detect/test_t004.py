#!/usr/bin/env python3

"""
test_t004.py

Test harness for validating the refactored T004 (Evil Twin) detection logic.
This script uses the new single-pass analysis engine and should be compared
against the output of the original t004.py script.
"""

import os
import sys
from tabulate import tabulate

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import from the new refactored analysis module
from helpers.refactored_analysis import (
    analyze_capture,
    detect_duplicate_handshakes,
    detect_rogue_aps,
    detect_beacon_anomalies,
    detect_client_traffic
)

# Import UI and parser helpers
from helpers.output import *
from helpers.parser import select_capture_file

def main():
    """
    Main function to orchestrate the test.
    """
    ui_clear_screen()
    ui_header("TEST HARNESS – T004 Refactored Logic")
    print_warning("This script is for validation purposes only.")
    print_blank()

    # Load Capture File
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Failed to load capture file. Aborting.")
        return

    print_blank()
    print_waiting("Running new single-pass analysis engine...")

    # --- Run the New Analysis Engine ---
    context = analyze_capture(cap)
    print_success("Analysis context created successfully.")
    print_blank()

    # --- Run Individual Detection Logics ---
    print_waiting("Detecting duplicate handshakes with refactored logic...")
    attack_chains = detect_duplicate_handshakes(context)

    print_waiting("Detecting rogue APs (SSID collisions)...")
    rogue_aps = detect_rogue_aps(context)

    print_waiting("Detecting beacon anomalies...")
    beacon_anomalies = detect_beacon_anomalies(context)

    print_waiting("Detecting encrypted client traffic...")
    client_traffic = detect_client_traffic(context)

    print_success("All detection logic executed.")
    print_blank()

    # --- Display Results ---
    print_prompt("Press Enter to display the results")
    input()
    ui_clear_screen()
    ui_header("TEST HARNESS – T004 Refactored Logic - Results")
    print_blank()

    def print_table(title, data, headers="keys"):
        if data:
            print_info(title)
            print(tabulate(data, headers=headers, tablefmt="outline"))
            print_blank()

    print_table("All Discovered Access Points:", list(context['access_points'].values()))
    print_table("Rogue APs (SSID Collisions):", rogue_aps)
    print_table("Beacon Anomalies:", beacon_anomalies)
    print_table("Detected Evil Twin Attack Chains:", attack_chains)
    print_table("Encrypted Client Traffic:", client_traffic)

    # --- Final Evaluation ---
    has_attack_chain = bool(attack_chains)
    has_traffic_with_rogue = False
    if has_attack_chain and client_traffic:
        rogue_ap_in_chain = attack_chains[0]['rogue_ap']
        has_traffic_with_rogue = any(t['ap'] == rogue_ap_in_chain for t in client_traffic)

    if attack_chains:
        if has_traffic_with_rogue:
            print_success("POSITIVE: A full Evil Twin attack chain with traffic was confirmed.")
        else:
            print_warning("PARTIAL: An Evil Twin re-association was found, but no subsequent traffic was confirmed.")
    elif rogue_aps or beacon_anomalies:
        print_warning("PARTIAL: Evidence of AP impersonation was found, but no client was observed being attacked.")
    else:
        print_success("NEGATIVE: No evidence of an Evil Twin attack was found.")

if __name__ == "__main__":
    main()