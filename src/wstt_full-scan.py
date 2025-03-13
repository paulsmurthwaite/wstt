#!/usr/bin/env python3
"""wstt_full-scan.py

Full Wi-Fi scanning tool using airodump-ng.
- Checks interface status and enables monitor mode if needed.
- Captures all visible SSIDs, BSSIDs, encryption types, and clients.
- Stores results as `all-traffic-scan-YYYYMMDDhhmmss.csv`.
- Runs indefinitely until the user presses CTRL+C.
- Ensures clean termination with no lingering processes.

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""


import os
import time
import subprocess
import sys
import logging
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
logger.setLevel(logging.INFO)

if not logger.hasHandlers():
    log_handler = logging.FileHandler(log_file)
    log_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    logger.addHandler(log_handler)

def scan_all_traffic(interface):
    """Runs airodump-ng, captures all visible Wi-Fi traffic, and ensures a clean exit."""

    if not check_interface_exists(interface):
        logger.error(f"Interface {interface} not found.")
        sys.exit(1)

    # Ensure monitor mode is enabled
    current_mode = get_interface_mode(interface)
    if current_mode == "managed":
        logger.info(f"{interface} is in Managed mode. Switching to Monitor mode...")
        enable_mode(interface, "monitor")
        time.sleep(2)
    elif current_mode == "monitor":
        logger.info(f"{interface} is already in Monitor mode.")
        time.sleep(2)
    else:
        logger.warning(f"Unable to determine mode. Resetting interface and retrying...")
        reset_interface(interface)
        time.sleep(2)
        enable_mode(interface, "monitor")

    # Generate filename using timestamp
    timestamp = time.strftime("%Y%m%d%H%M%S")  # Format: YYYYMMDDhhmmss
    output_file = f"wstt_full-scan-{timestamp}"

    stop_event = threading.Event()
    spinner_thread = threading.Thread(target=spinner, args=(stop_event,))
    spinner_thread.start()

    try:
        logger.info(f"Starting full scan on {interface}.")

        # Run airodump-ng as a controlled process
        process = subprocess.Popen(
            [
                "sudo", "airodump-ng",
                "--write", output_file,
                "--output-format", "csv",
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
        stop_event.set()
        spinner_thread.join()

    # Verify output file exists
    csv_file = f"{output_file}-01.csv"
    if os.path.exists(csv_file):
        logger.info(f"Full scan data saved to {csv_file}")
    else:
        logger.error("Airodump-ng did not produce an output file.")

    logger.info("Full scan complete.")
    time.sleep(3)

if __name__ == "__main__":
    interface = "wlx00c0cab4b58c"  # Set the correct wireless interface
    scan_all_traffic(interface)