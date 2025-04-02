#!/bin/bash

# T005 – Open Rogue Access Point
# Identifies APs with open (unencrypted) networks (Encryption == OPN)

# Usage: ./detect_t005.sh
# Requires: scan csv file

source ./config.sh
source ./helpers/validate_input.sh

# Header
echo ""
echo "[ T005 – Open Rogue Access Point Detection ]"

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

# Select scan file
CSV_FILE=$(select_csv_file) || exit 1
validate_csv_file "$CSV_FILE" || exit 1

# Basic detection
if [ "$DETECT_MODE" = "1" ]; then
    echo ""
    echo "[INFO] Running basic detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    echo "[RESULT] Detected Open (Unencrypted) Access Points:"
    echo "--------------------------------------------------"

    # Parse and output result
    awk -F',' '
        BEGIN { section=1 }
        /^$/ { section++; next }
        section==1 && NF > 14 {
            ssid=$14
            bssid=$1
            channel=$4
            encryption=$6
            gsub(/^ +| +$/, "", ssid)
            gsub(/^ +| +$/, "", bssid)
            gsub(/^ +| +$/, "", channel)
            gsub(/^ +| +$/, "", encryption)

            if (encryption == "OPN") {
                printf "  SSID: %-20s | BSSID: %-17s | Channel: %s\n", ssid, bssid, channel
            }
        }
    ' "$CSV_FILE"

    echo "--------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t005.py "$CSV_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi