#!/bin/bash

# T007 – Deauthentication Flood Detection
# Scans for a high volume of 802.11 deauth frames (subtype 12)

# Usage: ./detect_t007.sh
# Requires: .pcap capture file, tshark

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/../load_env.sh"

# Header
echo ""
echo "[ T007 – Deauthentication Flood Detection ]"

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
    DEAUTH_COUNT=$(tshark -r "$PCAP_FILE" -Y "wlan.fc.type_subtype == 12" 2>/dev/null | wc -l)

    # Output result
    if [ "$DEAUTH_COUNT" -gt 100 ]; then
        echo "[RESULT] FAIL – Deauthentication flood likely detected"
        echo "         Count: $DEAUTH_COUNT deauth frames"
    elif [ "$DEAUTH_COUNT" -gt 0 ]; then
        echo "[RESULT] WARNING – Some deauth frames observed (Count: $DEAUTH_COUNT)"
    else
        echo "[RESULT] PASS – No deauthentication frames found"
    fi
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t007.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi