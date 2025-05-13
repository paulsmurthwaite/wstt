#!/bin/bash

# T009 – Authentication Flood Detection
# Detects large volume of 802.11 authentication requests

# Usage: ./detect_t009.sh
# Requires: .pcap capture file, tshark

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/../fn_load-env.sh"

# Header
echo ""
echo "[ T009 – Authentication Flood Detection ]"

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
    # Count auth request frames (type_subtype 11)
    AUTH_COUNT=$(tshark -r "$PCAP_FILE" -Y "wlan.fc.type_subtype == 11" 2>/dev/null | wc -l)

    # Threshold (can move to config later)
    THRESHOLD=100

    # Output result
    if [ "$AUTH_COUNT" -gt "$THRESHOLD" ]; then
        echo "[RESULT] FAIL – Authentication flood likely detected"
        echo "         Count: $AUTH_COUNT authentication frames"
    elif [ "$AUTH_COUNT" -gt 0 ]; then
        echo "[RESULT] WARNING – Some authentication activity observed (Count: $AUTH_COUNT)"
    else
        echo "[RESULT] PASS – No authentication frames found"
    fi
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t009.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi