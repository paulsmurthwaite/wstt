#!/bin/bash

# T001 – Unencrypted Traffic Detection
# Scans a .pcap file for unencrypted protocols: HTTP, FTP, POP3, IMAP

# Usage: ./detect_t001.sh
# Requires: tshark

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/../load_env.sh"

# Header
echo ""
echo "[ T001 – Unencrypted Traffic Detection ]"

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
    MATCHING=$(tshark -r "$PCAP_FILE" \
        -Y "http || ftp || pop || imap" \
        -T fields \
        -e frame.number \
        -e frame.time_relative \
        -e ip.src \
        -e ip.dst -e \
        _ws.col.Protocol \
        2>/dev/null)

    # Output result
    if [ -z "$MATCHING" ]; then
        echo "[RESULT] PASS – No unencrypted traffic detected"
    else
        echo "[RESULT] FAIL – Unencrypted traffic found"
        echo "--------------------------------------------------"
        echo "$MATCHING"
        echo "--------------------------------------------------"
    fi
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t001.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi