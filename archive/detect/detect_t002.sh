#!/bin/bash

# T002 – Probe Request Snooping Detection
# Analyses scan .csv file for clients probing for known SSIDs

# Usage: ./detect_t002.sh
# Requires: scan csv file

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/../fn_load-env.sh"

# Header
echo ""
echo "[ T002 – Probe Request Snooping Detection ]"

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

    # Run detection & output result
    echo "[RESULT] Clients broadcasting probe requests:"
    echo "--------------------------------------------------"
   
    awk 'BEGIN {section=0}
         /^$/ {section++}
         section==2 && NF > 0 {
            split($0, fields, ",")
            mac=fields[1]
            essids=fields[NF]
            if (essids != "") {
                gsub(/^ +| +$/, "", mac)
                gsub(/^ +| +$/, "", essids)
                printf "  %s  →  %s\n", mac, essids
            }
         }' "$CSV_FILE"

    echo "--------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t002.py "$CSV_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi