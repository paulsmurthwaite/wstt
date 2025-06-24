#!/usr/bin/env python3

# ─── External Modules  ───
import os
import sys
from tabulate import tabulate

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ─── Local Modules ───
from helpers.ap_analysis import (
    detect_beacon_anomalies,
    detect_client_traffic,
    detect_client_disassociation,
    detect_duplicate_handshakes,
    detect_rogue_aps,
    get_known_aps
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
        "observations": []
    }

    # ─── Rogue APs ───
    print_waiting("SSID collisions (Rogue APs):")
    rogue_aps = detect_rogue_aps(cap)
    detection_result["rogue_aps"] = rogue_aps
    if rogue_aps:
        print_warning("SSID collision observed")
    else:
        print_error("No SSID collision observed")

    # ─── WPA2 Handshakes ───
    print_blank()
    print_waiting("Duplicate WPA2 handshakes:")
    dupes = detect_duplicate_handshakes(cap, known_aps)
    detection_result["duplicate_handshakes"] = dupes
    if dupes:
        print_warning("Duplicate WPA2 handshakes observed")
    else:
        print_error("No duplicate handshakes observed")

    # ─── Beacon Anomalies ───
    print_blank()
    print_waiting("Beacon anomalies:")
    beacons = detect_beacon_anomalies(cap)
    detection_result["beacon_anomalies"] = beacons
    if beacons:
        print_warning("Beacon anomalies observed")
    else:
        print_error("No beacon anomalies observed")

    # ─── Application-layer traffic ───
    print_blank()
    print_waiting("Application-layer traffic:")
    traffic = detect_client_traffic(cap, known_aps)
    detection_result["client_traffic"] = traffic
    if traffic:
        print_warning("Application-layer traffic observed")
    else:
        print_error("No application-layer traffic observed")

    # ─── Disassociation Frames ───
    print_blank()
    print_waiting("Client disconnection frames:")
    disassoc = detect_client_disassociation(cap, known_aps)
    detection_result["client_disconnections"] = disassoc
    if disassoc:
        print_warning("Client disconnection frames observed")
    else:
        print_error("No client disconnection frames observed")

    print_blank()
    print_prompt("Press Enter to display the summary")
    input()
    ui_clear_screen()

    # ─── Outcome Flags ───
    has_rogue = bool(rogue_aps)
    has_dupes = bool(dupes)
    has_traffic = bool(traffic)
    has_anomalies = bool(beacons)
    has_disassoc = bool(disassoc)

    # ─── Detection Outcome Evaluation ───
    if has_dupes and has_traffic:
        detection_result["status"] = "POSITIVE"
        detection_result["observations"] = [
            "Client completed handshakes with multiple APs",
            "Encrypted traffic was exchanged post-reassociation"
        ]
        if has_disassoc:
            detection_result["observations"].append("Client was forcibly disconnected before reassociation")
        if has_rogue or has_anomalies:
            detection_result["observations"].append("SSID/BSSID reuse or beacon fingerprint mismatch observed")
        detection_result["conclusion"] = "Sequence of events is consistent with Evil Twin impersonation"

    elif has_dupes:
        detection_result["status"] = "PARTIAL"
        detection_result["observations"] = [
            "Client reassociation with multiple APs detected"
        ]
        if has_disassoc:
            detection_result["observations"].append("Client was forcibly disconnected before reassociation")
        detection_result["conclusion"] = "Potential impersonation, but insufficient evidence to confirm"

    elif has_rogue or has_anomalies:
        detection_result["status"] = "PARTIAL"
        detection_result["observations"] = [
            "SSID reuse or BSSID spoofing inferred from beacon fingerprint anomalies"
        ]
        detection_result["conclusion"] = "Infrastructure anomaly observed; no client activity detected"

    else:
        detection_result["status"] = "NEGATIVE"
        detection_result["observations"] = [
            "No indicators of impersonation detected in capture",
            "No client activity consistent with Evil Twin behaviour"
        ]
        detection_result["conclusion"] = "No evidence of Evil Twin activity present"

    # ─── Final Summary Output ───
    ui_header("T004 – Evil Twin Detection - Summary")
    print_blank()

    def print_table(title, data, headers):
        if data:
            print_info(title)
            print(tabulate(data, headers=headers, tablefmt="outline"))
            print_blank()

    print_table("Rogue APs:", rogue_aps, {"ssid": "SSID", "bssids": "BSSIDs", "count": "Count"})

    # ─── Format Duplicate Handshake Summary ───
    dupes_summary = []
    for entry in dupes:
        evidence = "None"
        if entry["handshakes"]:
            evidence = "Full 4-way"
        elif entry["partial_type3_only"]:
            count = len(entry["partial_type3_only"])
            evidence = f"Partial (Type 3s: {count})"

        deauths = ""
        if entry["deauths_between"]:
            deauths = f"{len(entry['deauths_between'])} events"

        dupes_summary.append({
            "client": entry["client"],
            "ap": entry["ap"],
            "evidence": evidence,
            "deauths": deauths,
            "status": entry["status"]
        })

    print_table("Duplicate Handshakes:", dupes_summary, {
        "client": "Client MAC",
        "ap": "AP MAC",
        "evidence": "Handshakes",
        "deauths": "Deauths",
        "status": "Status"
    })
    
    print_table("Beacon Anomalies:", beacons, {"ssid": "SSID", "anomaly_type": "Anomaly", "bssids": "BSSIDs"})
    
    print_table("Client Traffic:", traffic, {"client": "Client MAC", "ap": "AP MAC", "frames": "Frame Count"})
    
    print_table("Client Disconnections:", disassoc, {"client": "Client MAC", "ap": "AP MAC", "frame_type": "Type", "frame_number": "Frame"})

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