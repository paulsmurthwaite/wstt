#!/bin/bash

# T004 – Evil Twin Attack
# Identifies duplicate SSIDs associated with multiple BSSIDs

# Usage: ./detect_t004.sh
# Requires: scan csv file

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/../load_env.sh"

# Header
echo ""
echo "[ T004 – Evil Twin Detection ]"

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

    # Run detection and output result
    awk 'BEGIN { FS=","; section=1 }
         /^$/ { section++; next }
         section==1 && NF > 14 {
             ssid=$14
             bssid=$1
             gsub(/^ +| +$/, "", ssid)
             gsub(/^ +| +$/, "", bssid)
             if (ssid != "") {
                 print ssid "|" bssid
             }
         }' "$CSV_FILE" | sort | uniq | awk -F'|' '
         {
             count[$1]++
             data[$1] = data[$1] "\n    → " $2
         }
         END {
             for (ssid in count) {
                 if (count[ssid] > 1) {
                     printf "SSID: \"%s\"\n%s\n\n", ssid, data[ssid]
                 }
             }
         }'

    echo "------------------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t004.py "$CSV_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi