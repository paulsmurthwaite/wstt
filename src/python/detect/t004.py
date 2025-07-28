#!/usr/bin/env python3

# ─── External Modules  ───
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.ap_analysis import (
    analyse_capture,
    detect_rogue_aps_context,
    detect_beacon_anomalies_context,
    detect_duplicate_handshakes_context,
    detect_client_traffic_context
)
from helpers.output import *
from helpers.parser import select_capture_file
from helpers.theme import *

def main():
    ui_clear_screen()
    ui_header("T004 – Evil Twin Detection")
    print_blank()
    print_waiting("Reading capture files")

    # ─── Load Capture ───
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    print_blank()
    print_waiting("Running single-pass analysis engine...")

    # --- Run the New Analysis Engine ---
    context = analyse_capture(cap)
    print_success("Analysis context created successfully.")
    print_blank()

    # --- Run Individual Detection Logics ---
    print_waiting("Detecting rogue APs (SSID collisions)...")
    rogue_aps = detect_rogue_aps_context(context)

    print_waiting("Detecting beacon anomalies...")
    beacon_anomalies = detect_beacon_anomalies_context(context)

    print_waiting("Detecting duplicate handshakes with refactored logic...")
    attack_chains = detect_duplicate_handshakes_context(context)

    print_waiting("Detecting encrypted client traffic...")
    client_traffic = detect_client_traffic_context(context)

    print_success("All detection logic executed.")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    # ─── Final Summary Output ───
    ui_header("T004 – Evil Twin Detection - Summary")
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

    # --- Determine Status and Conclusion ---
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