#!/bin/bash

# T008 – Beacon Flood Detection
# Counts excessive 802.11 beacon frames in a .pcap capture

# Usage: ./detect_t008.sh
# Requires: .pcap capture file, tshark

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/../fn_load-env.sh"

# Header
echo ""
echo "[ T008 – Beacon Flood Detection ]"

# Select detection mode
echo ""
echo "[+] Select detection mode:"
echo "    [1] Basic"
echo "    [2] Advanced"
read -rp "    → " DETECT_MODE

if [[ "$DETECT_MODE" != "1" && "$DETECT_MODE" != "2" ]]; then
    echo "[ERROR] Invalid selection. Choose 1 or 2."
    exit 1
fi

# Select capture file
PCAP_FILE=$(select_pcap_file) || exit 1
validate_pcap_file "$PCAP_FILE" || exit 1

# Basic detection
if [ "$DETECT_MODE" = "1" ]; then
    echo ""
    echo "[INFO] Running basic detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection
    # Count number of beacon frames (type_subtype == 8)
    BEACON_COUNT=$(tshark -r "$PCAP_FILE" -Y "wlan.fc.type_subtype == 8" 2>/dev/null | wc -l)

    # Define a threshold for flagging
    THRESHOLD=500

    # Output result
    if [ "$BEACON_COUNT" -gt "$THRESHOLD" ]; then
        echo "[RESULT] FAIL – Beacon flood likely detected"
        echo "         Count: $BEACON_COUNT beacon frames"
    elif [ "$BEACON_COUNT" -gt 0 ]; then
        echo "[RESULT] WARNING – Beacons observed (Count: $BEACON_COUNT)"
    else
        echo "[RESULT] PASS – No beacon frames found"
    fi
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t008.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi