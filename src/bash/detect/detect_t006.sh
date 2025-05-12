#!/bin/bash

# T006 – Misconfigured Access Point Detection
# Flags weak configurations: WEP, WPA-only (without WPA2/WPA3)

# Usage: ./detect_t006.sh
# Requires: scan csv file

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/../load_env.sh"

# Header
echo ""
echo "[ T006 – Misconfigured Access Point Detection ]"

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
    printf "\n"
    echo "[INFO] Running basic detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    echo "[RESULT] Potentially Misconfigured Access Points:"
    echo "--------------------------------------------------"

    # Check for WEP or WPA-only in Info field
    awk -F',' '
        BEGIN { section=1 }
        /^$/ { section++; next }
        section==1 && NF > 14 {
            ssid=$14
            bssid=$1
            channel=$4
            encryption=$6
            info=$NF
            gsub(/^ +| +$/, "", ssid)
            gsub(/^ +| +$/, "", bssid)
            gsub(/^ +| +$/, "", channel)
            gsub(/^ +| +$/, "", encryption)
            gsub(/^ +| +$/, "", info)

            if (encryption == "WEP") {
                printf "  [WEP]  SSID: %-20s | BSSID: %-17s | Channel: %s\n", ssid, bssid, channel
            }
            else if (encryption == "WPA" && info !~ /WPA2|WPA3/) {
                printf "  [WPA-Only]  SSID: %-16s | BSSID: %-17s | Channel: %s\n", ssid, bssid, channel
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

    # Run detection: python3 ./analysis/detect_t006.py "$CSV_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi