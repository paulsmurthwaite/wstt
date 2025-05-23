#!/bin/bash

# T015 – Malicious Hotspot Auto-Connect Detection
# Lists clients sending association requests to SSIDs

# Usage: ./detect_t014.sh
# Requires: .pcap capture file, tshark

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/../fn_load-env.sh"

# Header
echo ""
echo "[ T015 – Malicious Hotspot Auto-Connect Detection ]"

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

    echo "[RESULT] Client association attempts (Auto-connect candidates):"
    echo "--------------------------------------------------"

    # Run detection
    tshark -r "$PCAP_FILE" \
        -Y "wlan.fc.type_subtype == 0" \
        -T fields -e wlan.sa -e wlan.ssid 2>/dev/null |
    awk '
    {
        mac = $1
        ssid = $2
        if (mac != "") {
            if (ssid == "") ssid = "[Hidden or Unknown]"
            printf "  Client: %-17s → SSID: %s\n", mac, ssid
        }
    }'

    echo "--------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t015.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi