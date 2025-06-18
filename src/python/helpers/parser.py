import os
from pathlib import Path
import pyshark
from helpers.output import *

# ─── Configuration ───
CAPTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "output", "captures"))

# ─── Main PCAP Selection Utility ───
def select_capture_file(load=True):
    """
    Prompts the user to select a PCAP file from the captures directory.

    Args:
        load (bool): Whether to return a pyshark.FileCapture object or just the file path

    Returns:
        tuple: (str file_path, pyshark.FileCapture or None)
    """
    capture = None

    pcap_files = sorted(
        [f for f in Path(CAPTURE_DIR).glob("*.pcap")],
        key=lambda f: f.stat().st_mtime,
        reverse=True
    )

    if not pcap_files:
        print_error("No PCAP files found in captures directory.")
        return None, None

    print_info("Available capture files:")
    for idx, f in enumerate(pcap_files):
        print(f"  [{idx}] {f.name}")

    print_blank()
    print_prompt("Select PCAP file [default = 0]: ")
    choice = input().strip()

    if choice == "":
        index = 0
    else:
        try:
            index = int(choice)
            if index < 0 or index >= len(pcap_files):
                raise ValueError
        except ValueError:
            print_warning("Invalid selection.  Defaulting to latest file.")
            index = 0

    selected_file = str(pcap_files[index])
    print_success(f"Selected: {os.path.basename(selected_file)}")

    if load:
        try:
            print_blank()
            print_waiting("Loading capture file")
            capture = pyshark.FileCapture(selected_file, keep_packets=True)
            print_waiting("Capture file loaded - reading data")
        except Exception as e:
            print_error("Failed to load capture file")
            import traceback
            print(traceback.format_exc())
            return selected_file, None

    return selected_file, capture