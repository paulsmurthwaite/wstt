#!/usr/bin/env python3
"""wstt_target-scan.py

Targeted Wi-Fi scanning tool using airodump-ng.
- Reads the latest full scan CSV file.
- Displays available SSIDs and BSSIDs for selection.
- Starts a targeted scan filtering for the chosen AP.
- Stores results in `target-scan-YYYYMMDDhhmmss.csv`.
- Runs indefinitely until the user presses CTRL+C.
- Ensures clean termination with no lingering processes.

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import argparse
import os
import time
import subprocess
import sys
import logging
import csv
import threading
from wstt_utils import (
    check_interface_exists,
    get_interface_mode,
    enable_mode,
    reset_interface,
    spinner
)

# Define log directory and file
log_dir = os.path.join(os.path.dirname(__file__), "logs")
os.makedirs(log_dir, exist_ok=True)  # Create logs/ if missing

log_file = os.path.join(log_dir, "wstt.log")  # Unified log file for all scripts

# Configure logging
logger = logging.getLogger("wstt")

# Avoid adding duplicate handlers
if not logger.hasHandlers():
    logger.setLevel(logging.INFO)  # Default level

    # File logging (stores all logs)
    log_handler = logging.FileHandler(log_file)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    log_handler.setFormatter(formatter)
    log_handler.setLevel(logging.INFO)  # Store all logs
    logger.addHandler(log_handler)

    # Console error logging (shows only errors)
    error_handler = logging.StreamHandler()  # Send errors to terminal
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)  # Only show ERROR messages
    logger.addHandler(error_handler)

# Define scans directory
scans_dir = os.path.join(os.path.dirname(__file__), "scans")
os.makedirs(scans_dir, exist_ok=True)  # Create scans/ if missing


def get_latest_scan():
    """Finds the most recent full scan CSV file inside the scans/ directory."""
    scans_dir = os.path.join(os.path.dirname(__file__), "scans")
    
    # Ensure the scans directory exists
    if not os.path.exists(scans_dir):
        logger.error("[ERROR] Scans directory not found.")
        return None

    scan_files = sorted(
        [os.path.join(scans_dir, f) for f in os.listdir(scans_dir) if f.startswith("wstt_full-scan-") and f.endswith("-01.csv")],
        key=os.path.getmtime,
        reverse=True
    )

    return scan_files[0] if scan_files else None


def extract_ap_list(csv_file):
    """Extracts SSIDs, BSSIDs, and Channels from the latest full scan CSV."""
    ap_list = []
    parsing_aps = False  # Track when we are in the AP section

    try:
        with open(csv_file, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                # Skip empty rows silently
                if not row or all(field.strip() == "" for field in row):
                    continue  # No logging for purely empty rows

                # Identify where AP section begins (BSSID header)
                if row[0] == "BSSID":
                    parsing_aps = True  # Now we're reading APs, not clients
                    continue

                # Identify where Station (client) section begins and stop parsing
                if row[0] == "Station MAC":
                    parsing_aps = False
                    break

                if parsing_aps and len(row) >= 14:
                    if ":" not in row[0]:  # Ensure valid BSSID format
                        logger.warning(f"Skipping invalid BSSID row: {row}")
                        continue

                    ap_list.append({
                        "BSSID": row[0],
                        "Channel": row[3].strip(),  # Ensure proper formatting
                        "Power": row[8],  # Signal strength
                        "Encryption": row[5],
                        "SSID": row[13] if len(row) > 13 else "Unknown"
                    })

    except Exception as e:
        logger.error(f"Failed to read scan file: {e}")

    return ap_list


def select_target_ap(ap_list):
    """Displays available APs and allows the operator to select one."""
    print("\nAvailable Access Points:")
    for i, ap in enumerate(ap_list):
        print(f"{i+1}) BSSID: {ap['BSSID']} | SSID: {ap['SSID']} | Channel: {ap['Channel']} | Signal: {ap['Power']} dBm | Encryption: {ap['Encryption']}")

    while True:
        try:
            choice = int(input("\nSelect an AP by number: ")) - 1
            if 0 <= choice < len(ap_list):
                return ap_list[choice]
            print("[ERROR] Invalid selection. Please enter a valid number.")
        except ValueError:
            print("[ERROR] Invalid input. Please enter a number.")


def scan_target_ap(interface, target_ap):
    """Runs a targeted scan for a specific AP using airodump-ng."""

    # Ensure monitor mode is enabled
    if not check_interface_exists(interface):
        logger.error(f"Interface {interface} not found.")
        sys.exit(1)

    current_mode = get_interface_mode(interface)
    if current_mode == "managed":
        logger.info(f"{interface} is in Managed mode. Switching to Monitor mode...")
        enable_mode(interface, "monitor")
        time.sleep(2)

    # Generate filename using timestamp in scans/ directory
    timestamp = time.strftime("%Y%m%d%H%M%S")  # Format: YYYYMMDDhhmmss
    output_file = os.path.join(scans_dir, f"wstt_target-scan-{timestamp}")

    # Start spinner thread
    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(stop_event,))
    spinner_thread.start()

    try:
        logger.info(f"Starting targeted scan for {target_ap['SSID']} ({target_ap['BSSID']}) on Channel {target_ap['Channel']}.")

        # Run airodump-ng as a controlled process
        process = subprocess.Popen(
            [
                "sudo", "airodump-ng",
                "--bssid", target_ap["BSSID"],
                "--channel", str(target_ap["Channel"]),
                "--output-format", "csv",
                "--write", output_file,
                interface
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            text=True
        )

        # Run indefinitely until manually stopped
        process.wait()

    except KeyboardInterrupt:
        logger.info("Scan stopped by user. Cleaning up...")

        # Ensure process is terminated
        process.terminate()
        process.wait()

        # Kill any lingering airodump-ng processes
        subprocess.run(["sudo", "pkill", "-f", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    except subprocess.CalledProcessError:
        logger.error(f"Failed to start scanning on {interface}.")
        sys.exit(1)

    finally:
        # Stop spinner thread
        stop_event.set()
        spinner_thread.join()

    # Verify output file exists
    csv_file = f"{output_file}-01.csv"
    if os.path.exists(csv_file):
        logger.info(f"Target scan data saved to {csv_file}")
    else:
        logger.error("Airodump-ng did not produce an output file.")

    logger.info("Target scan complete.")
    time.sleep(3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Targeted Wi-Fi scan using airodump-ng.")
    parser.add_argument("-i", "--interface", required=True, help="Wireless interface to use for scanning")
    args = parser.parse_args()

    latest_scan = get_latest_scan()
    if not latest_scan:
        print("[ERROR] No previous scan found. Run `wstt_full-scan.py` first.")
        sys.exit(1)

    logger.info(f"Using latest scan file: {latest_scan}")
    ap_list = extract_ap_list(latest_scan)

    if not ap_list:
        logger.error("No access points found in the last scan.")
        sys.exit(1)

    target_ap = select_target_ap(ap_list)
    scan_target_ap(args.interface, target_ap)
