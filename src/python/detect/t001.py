#!/usr/bin/env python3

import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from helpers.ap_analysis import (
    parse_ap_frames,
    find_client_associations,
    inspect_unencrypted_frames 
)
from helpers.parser import select_capture_file
from helpers.output import *
from helpers.theme import *

def main():
    ui_clear_screen()
    ui_header("T001 – Unencrypted Traffic Capture")
    print_blank()
    print_waiting("Reading capture files")

    # ─── Load Capture ───
    path, cap = select_capture_file(load=True)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    print_blank()
    print_waiting("Parsing for Access Points")
    access_points = parse_ap_frames(cap)

    detection_result = {
        "aps": access_points,
        "client_associations": [],
        "unencrypted_flows": [],
        "status": "NEGATIVE",
        "risk_level": "None",
        "justification": []
    }

    open_aps = [ap for ap in access_points if not ap["privacy"] and not ap["rsn"]]
    if open_aps:
        for ap in open_aps:
            print_warning(f"Open network observed: {ap['ssid']} ({ap['bssid']})")
    else:
        print_error("No open network observed.")

    print_success("AP parsing complete.")

    # ─── Client Association ───
    print_blank()
    print_waiting("Parsing for Client ⇄ AP association:")
    client_links = find_client_associations(cap, access_points)
    if client_links:
        print_warning("Client ⇄ AP Communication observed")
        detection_result["client_associations"] = client_links
    else:
        print_error("No Client ⇄ AP Communication observed")

    print_success("Client ⇄ AP association parsing complete.")

    # ─── Unencrypted Traffic Analysis ───
    print_blank()
    print_waiting("Parsing for unencrypted application-layer traffic")
    unencrypted = inspect_unencrypted_frames(cap)
    if unencrypted:
        print_warning("Unencrypted communication observed")
        detection_result["unencrypted_flows"] = unencrypted
    else:
        print_error("No unencrypted communication observed")

    print_success("Unencrypted application-layer traffic analysis complete")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    # ─── Determine Detection Outcome ───
    if open_aps and client_links and unencrypted:
        detection_result["status"] = "POSITIVE"
        detection_result["risk_level"] = "High"
        detection_result["justification"] = [
            "Open AP detected",
            "Client communication observed",
            "Readable payload confirmed"
        ]
    elif open_aps and (client_links or unencrypted):
        detection_result["status"] = "PARTIAL"
        detection_result["risk_level"] = "Moderate"
        detection_result["justification"] = [
            "Open AP detected",
            "Partial evidence chain",
            "Some client activity or readable data present"
        ]
    elif open_aps:
        detection_result["status"] = "PARTIAL"
        detection_result["risk_level"] = "Low"
        detection_result["justification"] = [
            "Open AP detected",
            "No client traffic or readable data observed"
        ]
    else:
        detection_result["status"] = "NEGATIVE"
        detection_result["risk_level"] = "None"
        detection_result["justification"] = [
            "No Open APs detected",
            "No client associations",
            "No readable payloads"
        ]

    # ─── Final Summary Output ───
    ui_header("T001 – Unencrypted Traffic Capture Detection - Summary")
    print_blank()

    if detection_result["aps"]:
        print_info("Access Points:")
        print(tabulate(
            detection_result["aps"],
            headers={"ssid": "SSID", "bssid": "BSSID", "privacy": "Privacy", "rsn": "RSN"},
            tablefmt="outline"
        ))
        print_blank()

    if detection_result["client_associations"]:
        print_info("Client Associations:")
        print(tabulate(
            detection_result["client_associations"],
            headers={"client": "Client MAC", "ap": "AP MAC", "frames": "Frame Count"},
            tablefmt="outline"
        ))
        print_blank()

    if detection_result["unencrypted_flows"]:
        print_info("Unencrypted Flows:")
        print(tabulate(
            detection_result["unencrypted_flows"],
            headers={"client": "Client MAC", "ap": "AP MAC", "frames": "Frame Count", "layers": "Visible Layers"},
            tablefmt="outline"
        ))
        print_blank()

    if detection_result["status"] == "POSITIVE":
        print_error("Detection Result: POSITIVE")
    elif detection_result["status"] == "NEGATIVE":
        print_success("Detection Result: NEGATIVE")
    else:
        print_warning("Detection Result: PARTIAL")

    print_info(f"Risk Level: {detection_result['risk_level']}")
    print_blank()
    print_info("Justification:")
    for line in detection_result["justification"]:
        print_none(f"- {line}")
    print_blank()
    print_success("T001 – Unencrypted Traffic Capture Detection - Complete")

if __name__ == "__main__":
    main()