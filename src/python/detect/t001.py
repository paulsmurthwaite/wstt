#!/usr/bin/env python3

# ─── External Modules ───
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.ap_analysis import analyse_capture, detect_unencrypted_traffic_context
from helpers.output import *
from helpers.parser import select_capture_file
from helpers.theme import *

def main():
    ui_clear_screen()
    ui_header("T001 – Unencrypted Traffic Capture Detection")
    print_blank()

    # ─── Load Capture ───
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    # --- Run Analysis ---
    context = analyse_capture(cap)
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

    # ─── Final Summary Output ───
    ui_header("T001 – Unencrypted Traffic Capture Detection - Summary")
    print_blank()

    def print_table(title, data, headers="keys"):
        if data:
            print_info(title)
            print(tabulate(data, headers=headers, tablefmt="outline"))
            print_blank()

    if all_aps:
        print_info("Access Points:")
        print(tabulate(
            all_aps,
            headers={"bssid": "BSSID", "ssid": "SSID", "channel": "CH", "privacy": "Privacy", "rsn": "RSN"},
            tablefmt="outline"
        ))
        print_blank()

    if unencrypted_flows:
        print_info("Unencrypted Flows:")
        print(tabulate(
            unencrypted_flows,
            headers={"client": "Client MAC", "ap": "AP MAC", "frames": "Frame Count", "layers": "Visible Layers"},
            tablefmt="outline"
        ))
        print_blank()

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