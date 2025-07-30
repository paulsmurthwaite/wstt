#!/usr/bin/env python3
"""parser.py

Provides a user-facing file selection utility for the WSTT.

This module is responsible for locating packet capture (`.pcap`) files within
the directory specified in the project's configuration. It presents an
interactive menu for the user to select a file and uses the Scapy library
to load the selected capture into memory for analysis by the detection scripts.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import os
import json
import sys
import threading
import itertools
import time
from scapy.all import rdpcap

# ─── Local Modules ───
from helpers.output import (
    print_action,
    print_blank,
    print_error,
    print_prompt,
    print_success,
    print_waiting,
)
from helpers.theme import colour

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

CONFIG_PATH = os.path.join(PROJECT_ROOT, "src", "python", "config", "config.json")

try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        relative_capture_path = config["paths"]["capture_directory"]
        python_base_dir = os.path.join(PROJECT_ROOT, "src", "python")
        CAPTURE_DIR = os.path.abspath(os.path.join(python_base_dir, relative_capture_path))
except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
    print_error(f"Failed to load capture directory from config: {e}")
    CAPTURE_DIR = os.path.join(PROJECT_ROOT, "src", "output", "captures")

def select_capture_file(load=True):
    """
    Presents a menu to select a capture file and optionally load it.

    This function scans the configured capture directory for `.pcap` files,
    displays them in a numbered list to the user, and prompts for a selection.
    It can either return the path to the selected file or load it into memory
    using Scapy.

    Args:
        load (bool): If True, the selected `.pcap` file is loaded using
            Scapy's rdpcap and returned as a packet list. If False,
            only the file path is returned. Defaults to True.

    Returns:
        tuple: A tuple containing two elements:
            - The absolute filepath (str) to the selected capture file.
            - A Scapy PacketList object if `load` is True, otherwise None.
        Returns (None, None) if no file is selected or an error occurs.
    """
    try:
        files = sorted(
            [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcap")],
            key=lambda f: os.path.getmtime(os.path.join(CAPTURE_DIR, f)),
            reverse=True,
        )

        if not files:
            print_error(f"No .pcap files found in the configured directory: {CAPTURE_DIR}")
            return None, None

        print_action("Available capture files:")
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

        # --- Spinner implementation for long-running file load ---
        done = False
        def animate():
            """Function to run in a separate thread to display a spinner."""
            for c in itertools.cycle(['|', '/', '-', '\\']):
                if done:
                    break
                # Use our theme's colour for consistency
                spinner_text = f'\r{colour("[~]", "info")} Loading capture file {c}'
                sys.stdout.write(spinner_text)
                sys.stdout.flush()
                time.sleep(0.1)
            # Clear the line after finishing
            sys.stdout.write('\r' + ' ' * (len(spinner_text) + 5) + '\r')

        t = threading.Thread(target=animate)
        t.start()

        packets = rdpcap(selected_file) # This is the long-running task
        done = True
        t.join() # Wait for the animation thread to finish cleanly

        print_success(f"Capture file loaded successfully ({len(packets)} packets)")
        return selected_file, packets

    except FileNotFoundError:
        print_error(f"Capture directory not found: {CAPTURE_DIR}")
        return None, None
    except Exception as e:
        print_error(f"An unexpected error occurred in the parser: {e}")
        return None, None