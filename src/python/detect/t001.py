#!/usr/bin/env python3

# ─── External Modules ───
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.ap_analysis import (
    find_client_associations,
    inspect_unencrypted_frames,
    parse_ap_frames
)
from helpers.output import *
from helpers.parser import select_capture_file
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
    print_waiting("Open wireless networks:")
    access_points = parse_ap_frames(cap)

    detection_result = {
        "aps": access_points,
        "client_associations": [],
        "unencrypted_flows": [],
        "status": "NEGATIVE",
        "observations": [],
        "conclusion": "",
    }

    open_aps = [ap for ap in access_points if not ap["privacy"] and not ap["rsn"]]
    if open_aps:
        for ap in open_aps:
            print_warning(f"Open wireless network observed: {ap['ssid']} ({ap['bssid']})")
    else:
        print_error("No open wireless network observed")

    # ─── Client Association ───
    print_blank()
    print_waiting("Client-device associations:")
    client_links = find_client_associations(cap, access_points)
    if client_links:
        print_warning("Client-device associations observed")
        detection_result["client_associations"] = client_links
    else:
        print_error("No Client-device associations observed")

    # ─── Unencrypted Traffic Analysis ───
    print_blank()
    print_waiting("Unencrypted application-layer traffic:")
    unencrypted = inspect_unencrypted_frames(cap)
    if unencrypted:
        print_warning("Unencrypted application-layer traffic observed")
        detection_result["unencrypted_flows"] = unencrypted
    else:
        print_error("No unencrypted application-layer traffic observed")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    # ─── Outcome Flags ───
    has_open_ap = bool(open_aps)
    has_unencrypted = bool(unencrypted)
    has_client_links = bool(client_links)

    # ─── Detection Outcome Evaluation ───
    if has_open_ap and has_unencrypted:
        detection_result["status"] = "POSITIVE"
        detection_result["observations"] = [
            "Open AP detected",
            "Readable payload confirmed",
            "Client communication observed"
        ]
        detection_result["conclusion"] = "Unencrypted client communication over open wireless observed"

    elif has_open_ap and (has_client_links or has_unencrypted):
        detection_result["status"] = "PARTIAL"
        detection_result["observations"] = [
            "Open AP detected",
            "Partial evidence chain",
            "Some client activity or readable data present"
        ]
        detection_result["conclusion"] = "Partial exposure detected via open AP or client behaviour"

    elif has_open_ap:
        detection_result["status"] = "PARTIAL"
        detection_result["observations"] = [
            "Open AP detected",
            "No client traffic or readable data observed"
        ]
        detection_result["conclusion"] = "Open wireless detected, but no unencrypted traffic observed"

    else:
        detection_result["status"] = "NEGATIVE"
        detection_result["observations"] = [
            "No Open APs detected",
            "No client associations",
            "No readable payloads"
        ]
        detection_result["conclusion"] = "No exposure to unencrypted wireless traffic detected"

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

    print_info("Observations:")
    for line in detection_result["observations"]:
        print_none(f"- {line}")
    print_blank()

    if detection_result["status"] == "POSITIVE":
        print_error("Detection Result: POSITIVE")
    elif detection_result["status"] == "NEGATIVE":
        print_success("Detection Result: NEGATIVE")
    else:
        print_warning("Detection Result: PARTIAL")

    print_none(f"- {detection_result['conclusion']}")

if __name__ == "__main__":
    main()