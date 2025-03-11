#!/usr/bin/env python3

import os
import sys
import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
import argparse
from wstt_managed import enable_managed_mode
from wstt_monitor import enable_monitor_mode

def ensure_root():
    """Ensure the script is run as root."""
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root.")
        sys.exit(1)

def scan_wifi(interface):
    """Scans for Wi-Fi networks by capturing beacon frames"""

    ensure_root()  # Ensure we have root access

    enable_monitor_mode(interface)  # Enable monitor mode

    networks = {}

    def packet_handler(pkt):
        """Processes captured packets"""
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            bssid = pkt[Dot11].addr2
            if bssid not in networks:
                networks[bssid] = ssid
                print(f"SSID: {ssid} | BSSID: {bssid}")

    print(f"Scanning for Wi-Fi networks on {interface}... (Press Ctrl+C to stop)")
    sniff(iface=interface, prn=packet_handler, timeout=10)

    enable_managed_mode(interface)  # Return to managed mode

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wi-Fi Scanner using Scapy")
    parser.add_argument("-i", "--interface", required=True, help="Wi-Fi interface to use (e.g., wlan0)")
    args = parser.parse_args()

    scan_wifi(args.interface)
