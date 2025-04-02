#!/bin/bash

# Set parameters
source ./config.sh
source ./helpers/validate_input.sh
OUTPUT_FILE="$SCN_DIR/wstt_scan-$FILE_BASE"

# Header
echo ""
echo "[ Traffic Scan ]"

# Select scan type
echo ""
echo "[+] Type:"
echo "    [1] Full"
echo "    [2] Filtered"
read -rp "    → " SCAN_TYPE

# Full scan
if [ "$SCAN_TYPE" = "1" ]; then
    
    # Input band
    echo ""
    echo "[ Band Selection ]"
    echo ""
    echo "[+] Band:"
    echo "    [1] 2.4GHz"
    echo "    [2] 5GHz"
    read -rp "    → " BAND_SELECT

    # Selection handler
    if [ "$BAND_SELECT" = "1" ]; then
        CHANNELS="$CHANNELS_24GHZ_UK"
        BAND_LABEL="2.4ghz"
    elif [ "$BAND_SELECT" = "2" ]; then
        CHANNELS="$CHANNELS_5GHZ_UK"
        BAND_LABEL="5ghz"
    else
        echo "[ERROR] Invalid selection. Please select 1 or 2."
        exit 1
    fi

    # Input duration
    echo ""
    echo "[ Full Scan ($BAND_LABEL) ]"
    echo ""
    echo "[+] Duration (seconds) [default]: ${DEFAULT_SCAN_DURATION}]: "
    read -rp "    → " DURATION
    DURATION="${DURATION:-$DEFAULT_SCAN_DURATION}"
    validate_duration "$DURATION"

    # Set output filename
    OUTPUT_FILE="$SCN_DIR/wstt_scan-full-${BAND_LABEL}-$FILE_BASE"

    # Run scan
    sudo timeout "$DURATION" \
        airodump-ng "$INTERFACE" \
        --channel "$CHANNELS" \
        --write "$OUTPUT_FILE" \
        --output-format csv

    # Rename file
    mv "${OUTPUT_FILE}-01.csv" "${OUTPUT_FILE}.csv"

    # File output
    if [ -f "${OUTPUT_FILE}.csv" ]; then
        printf "\n[INFO] Scan complete.\n"
        echo "[INFO] Applied Parameters: Band=$BAND_LABEL | Channels=$CHANNELS | Duration=$DURATION seconds"
        echo "[INFO] Output saved to: $OUTPUT_FILE"
    else
        echo "[ERROR] Output file not found. Airodump-ng may have failed."
    fi

#  Filtered scan
elif [ "$SCAN_TYPE" = "2" ]; then

    # Input filter parameters
    echo ""
    echo "[ Filter Selection ]"
    echo ""
    echo "[+] BSSID: "
    read -rp "    → " BSSID
    validate_bssid "$BSSID"

    echo ""
    echo "[+] Channel: "
    read -rp "    → " CHANNEL
    validate_channel "$CHANNEL"

    echo ""
    echo "[+] Duration (seconds) [default]: ${DEFAULT_SCAN_DURATION}]: "
    read -rp "    → " DURATION
    DURATION="${DURATION:-$DEFAULT_SCAN_DURATION}"
    validate_duration "$DURATION"

    # Set output filename
    OUTPUT_FILE="$SCN_DIR/wstt_scan-filtered-$FILE_BASE"

    # Run scan
    sudo timeout "$DURATION" \
        airodump-ng "$INTERFACE" \
        --bssid "$BSSID" \
        --channel "$CHANNEL" \
        --write "$OUTPUT_FILE" \
        --output-format csv

    # Rename file
    mv "${OUTPUT_FILE}-01.csv" "${OUTPUT_FILE}.csv"

    # File output
    if [ -f "${OUTPUT_FILE}.csv" ]; then
        printf "\n[INFO] Scan complete.\n"
        echo "[INFO] Applied Filter: BSSID=$BSSID | Channel=$CHANNEL | Duration=$DURATION seconds"
        echo "[INFO] Output saved to: $OUTPUT_FILE"
    else
        echo "[ERROR] Output file not found. Airodump-ng may have failed."
    fi

else
    echo "[ERROR] Invalid Scan type. Please enter 1 or 2."
    exit 1
fi