#!/bin/bash

# T003 – SSID Harvesting Detection
# Extracts unique SSIDs probed by client devices

# Usage: ./detect_t003.sh
# Requires: scan csv file

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/../fn_load-env.sh"

# Header
echo ""
echo "[ T003 – SSID Harvesting Detection ]"

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

    echo "[RESULT] Probed SSIDs (Harvested from client requests):"
    echo "--------------------------------------------------"

    # Parse
    awk -F',' '
        BEGIN { section=0 }
        /^$/ { section++ }
        section==2 && NF > 0 {
            ssids=$NF
            split(ssids, essid_list, /[;|]/)
            for (i in essid_list) {
                gsub(/^ +| +$/, "", essid_list[i])
                if (essid_list[i] != "")
                    seen[essid_list[i]]++
            }
        }
        END {
            for (ssid in seen) {
                print "  → " ssid
            }
        }
    ' "$CSV_FILE" | sort

    echo "--------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$CSV_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t003.py "$CSV_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi