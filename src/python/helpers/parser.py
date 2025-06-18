#!/usr/bin/env python3

"""
parser.py

Helper module to select and optionally load PCAP files using Scapy.

Author: Paul Smurthwaite
"""

import os
from scapy.all import rdpcap
from helpers.output import *
import json

CONFIG_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
)

# Load capture directory path from config
try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        CAPTURE_DIR = os.path.abspath(os.path.join(os.path.dirname(CONFIG_PATH), "..", config["paths"]["capture_directory"]))
except Exception as e:
    print_error(f"Failed to load capture directory from config: {e}")
    CAPTURE_DIR = "./output/captures"

def select_capture_file(load=True):
    """
    Presents a list of available PCAP files and allows user to select one.
    If load=True, returns both the filepath and loaded Scapy packet list.
    If load=False, returns filepath and None.

    Returns:
        (filepath, capture) or (None, None) on failure.
    """
    try:
        files = sorted(
            [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")],
            reverse=True
        )

        if not files:
            print_error("No capture files found.")
            return None, None

        # Display options
        print_action("Available PCAP Files:")
        for idx, fname in enumerate(files, 1):
            print(f"    [{idx}] {fname}")

        print_blank()
        print_prompt("Select a capture file [1 = default]: ")
        choice = input().strip()

        if not choice:
            selected_file = os.path.join(CAPTURE_DIR, files[0])
        elif choice.isdigit() and 1 <= int(choice) <= len(files):
            selected_file = os.path.join(CAPTURE_DIR, files[int(choice) - 1])
        else:
            print_error("Invalid selection.")
            return None, None

        print_action(f"Selected: {os.path.basename(selected_file)}")

        if not load:
            return selected_file, None

        # Load with Scapy
        print_waiting("Loading capture file")
        packets = rdpcap(selected_file)
        print_success("Capture file loaded")
        return selected_file, packets

    except Exception as e:
        print_error(f"Parser failed: {e}")
        return None, None
