#!/usr/bin/env python3

import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from helpers.ap_analysis import (
    detect_rogue_aps,
    detect_duplicate_handshakes,
    detect_beacon_anomalies,
    detect_client_traffic,
    detect_client_disassociation,
    get_known_aps
)
from helpers.parser import select_capture_file
from helpers.output import *
from helpers.theme import *

def main():
    ui_clear_screen()
    ui_header("T004 – Evil Twin Detection")
    print_blank()
    print_waiting("Reading capture files")

    # ─── Load Capture ───
    path, cap = select_capture_file(load=True)
    known_aps = get_known_aps(cap)
    if cap is None:
        print_error("Capture object was not returned.")
        return

    print_blank()
    detection_result = {
        "rogue_aps": [],
        "duplicate_handshakes": [],
        "beacon_anomalies": [],
        "client_traffic": [],
        "client_disconnections": [],
        "status": "NEGATIVE",
        "risk_level": "None",
        "justification": []
    }

    # ─── Detection Passes ───
    print_waiting("Detecting Rogue APs...")
    rogue_aps = detect_rogue_aps(cap)
    detection_result["rogue_aps"] = rogue_aps
    if rogue_aps:
        print_warning("SSID collision detected")
    else:
        print_error("No SSID collision detected")

    print_waiting("Analysing WPA2 Handshakes...")
    dupes = detect_duplicate_handshakes(cap, known_aps)
    detection_result["duplicate_handshakes"] = dupes
    if dupes:
        print_warning("Duplicate WPA2 handshakes detected")
    else:
        print_error("No duplicate handshakes detected")

    print_waiting("Checking for Beacon Anomalies...")
    beacons = detect_beacon_anomalies(cap)
    detection_result["beacon_anomalies"] = beacons
    if beacons:
        print_warning("Beacon anomalies detected")
    else:
        print_error("No beacon anomalies detected")

    print_waiting("Checking Client Traffic...")
    traffic = detect_client_traffic(cap)
    detection_result["client_traffic"] = traffic
    if traffic:
        print_warning("Client traffic with multiple APs detected")
    else:
        print_error("No encrypted traffic exchange detected")

    print_waiting("Looking for Disassociation Frames...")
    disassoc = detect_client_disassociation(cap)
    detection_result["client_disconnections"] = disassoc
    if disassoc:
        print_warning("Client disconnection frames detected")
    else:
        print_error("No disconnection frames found")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    # ─── Detection Outcome Evaluation ───
    has_rogue = bool(rogue_aps)
    has_dupes = bool(dupes)
    has_traffic = bool(traffic)
    has_anomalies = bool(beacons)

    if has_dupes and has_traffic:
        detection_result["status"] = "POSITIVE"
        detection_result["risk_level"] = "High"
        detection_result["justification"] = [
            "Client reassociated with multiple APs",
            "Encrypted communication observed",
            "Impersonation likely based on frame evidence"
        ]
        if has_rogue or has_anomalies:
            detection_result["justification"].append("SSID/BSSID or beacon anomaly detected")
    elif has_dupes:
        detection_result["status"] = "PARTIAL"
        detection_result["risk_level"] = "Moderate"
        detection_result["justification"] = [
            "Client reassociation observed",
            "No traffic or anomalies confirmed"
        ]
    elif has_rogue or has_anomalies:
        detection_result["status"] = "PARTIAL"
        detection_result["risk_level"] = "Low"
        detection_result["justification"] = [
            "Suspicious SSID/BSSID activity detected",
            "No client behaviour observed"
        ]
    else:
        detection_result["status"] = "NEGATIVE"
        detection_result["risk_level"] = "None"
        detection_result["justification"] = [
            "No impersonation indicators found",
            "No client activity detected"
        ]

    # ─── Summary Output ───
    ui_header("T004 – Evil Twin Detection - Summary")
    print_blank()

    def print_table(title, data, headers):
        if data:
            print_info(title)
            print(tabulate(data, headers=headers, tablefmt="outline"))
            print_blank()

    print_table("Rogue APs:", rogue_aps, {"ssid": "SSID", "bssids": "BSSIDs", "count": "Count"})
    print_table("Duplicate Handshakes:", dupes, {"client": "Client MAC", "aps": "AP MACs", "count": "Count"})
    print_table("Beacon Anomalies:", beacons, {"ssid": "SSID", "anomaly_type": "Anomaly", "bssids": "BSSIDs"})
    print_table("Client Traffic:", traffic, {"client": "Client MAC", "ap": "AP MAC", "frames": "Frame Count"})
    print_table("Client Disconnections:", disassoc, {"client": "Client MAC", "ap": "AP MAC", "frame_type": "Type", "frame_number": "Frame"})

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
    print_success("T004 – Evil Twin Detection - Complete")

if __name__ == "__main__":
    main()
