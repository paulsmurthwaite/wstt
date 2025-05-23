#!/bin/bash

# ─── Paths ───
BASH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$BASH_DIR/config"
HELPERS_DIR="$BASH_DIR/helpers"
SERVICES_DIR="$BASH_DIR/services"
UTILITIES_DIR="$BASH_DIR/utilities"
OUTPUT_DIR="$BASH_DIR/../output"

# ─── Configs ───
source "$CONFIG_DIR/global.conf"
source "$CONFIG_DIR/scan.conf"

# ─── Helpers ───
source "$HELPERS_DIR/fn_print.sh"
source "$HELPERS_DIR/fn_mode.sh"

# ─── Output File ───
OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-$FILE_BASE"

# Input scan type
while true; do
    print_prompt "Scan Type: [1] Full [2] Filtered: "
    read -r SCAN_TYPE

    if [[ "$SCAN_TYPE" == "1" || "$SCAN_TYPE" == "2" ]]; then
        break
    else
        print_fail "Invalid selection. Please enter 1 or 2"
    fi
done

# Full scan
if [ "$SCAN_TYPE" = "1" ]; then
    
    # Input band
    while true; do
        print_prompt "Band: [1] 2.4GHz [2] 5GHz: "
        read -r BAND_SELECT

        if [[ "$BAND_SELECT" == "1" ]]; then
            CHANNELS="$CHANNELS_24GHZ_UK"
            BAND_LABEL="2.4ghz"
            break
        elif [[ "$BAND_SELECT" == "2" ]]; then
            CHANNELS="$CHANNELS_5GHZ_UK"
            BAND_LABEL="5ghz"
            break
        else
            print_fail "Invalid selection. Please enter 1 or 2"
        fi
    done

    # Input duration
    while true; do
        print_prompt "Duration (seconds) [default]: ${DEFAULT_SCAN_DURATION}]: "
        read -r DURATION

        DURATION="${DURATION:-$DEFAULT_SCAN_DURATION}"
        
        if [[ "$DURATION" =~ ^[0-9]+$ ]]; then
            break
        else
            print_fail "Invalid input. Enter a numeric value (seconds)"
        fi
    done

    # Output filename
    OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-full-${BAND_LABEL}-$FILE_BASE"

    # Check mode
    ensure_monitor_mode

    # Run scan
    sudo timeout "$DURATION" airodump-ng "$INTERFACE" --channel "$CHANNELS" --write "$OUTPUT_FILE" --output-format csv

    # Rename file
    mv "${OUTPUT_FILE}-01.csv" "${OUTPUT_FILE}.csv"

    # Reset mode to Managed
    ensure_managed_mode

    # File output
    if [ -f "${OUTPUT_FILE}.csv" ]; then
        print_blank
        print_success "Scan complete"
        print_info "Scan parameters : Band=$BAND_LABEL | Channels=$CHANNELS | Duration=$DURATION seconds"
        print_info "Output file     : $OUTPUT_FILE"
    else
        print_fail "Output file not found. Airodump-ng may have failed"
    fi

#  Filtered scan
elif [ "$SCAN_TYPE" = "2" ]; then

    # Input BSSID
    while true; do
        print_prompt "BSSID (target AP): "
        read -r BSSID

        if [[ "$BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
            break
        else
            print_fail "Invalid BSSID format. Expected XX:XX:XX:XX:XX:XX"
        fi
    done

    VALID_CHANNELS="${CHANNELS_24GHZ_UK//,/ } ${CHANNELS_5GHZ_UK//,/ }"

    while true; do
        print_prompt "Channel: "
        read -r CHANNEL

        if [[ "$CHANNEL" =~ ^[0-9]+$ ]] && [[ $VALID_CHANNELS =~ (^|[[:space:]])$CHANNEL($|[[:space:]]) ]]; then
            break
        else
            print_fail "Invalid channel. Must be numeric and UK legal (2.4GHz or 5GHz)"
        fi
    done

    while true; do
        print_prompt "Duration (seconds) [default: ${DEFAULT_SCAN_DURATION}]: "
        read -r DURATION
        DURATION="${DURATION:-$DEFAULT_SCAN_DURATION}"

        if [[ "$DURATION" =~ ^[0-9]+$ ]]; then
            break
        else
            print_fail "Invalid input. Enter a numeric value (seconds)"
        fi
    done

    # Output filename
    OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-filtered-$FILE_BASE"

    # Check mode
    ensure_monitor_mode

    # Run scan
    sudo timeout "$DURATION" airodump-ng "$INTERFACE" --bssid "$BSSID" --channel "$CHANNEL" --write "$OUTPUT_FILE" --output-format csv

    # Rename file
    mv "${OUTPUT_FILE}-01.csv" "${OUTPUT_FILE}.csv"

    # Reset mode to Managed
    ensure_managed_mode

    # File output
    if [ -f "${OUTPUT_FILE}.csv" ]; then
        print_blank
        print_info "Scan complete"
        print_info "Applied Filter: BSSID=$BSSID | Channel=$CHANNEL | Duration=$DURATION seconds"
        print_info "Output saved to: $OUTPUT_FILE"
    else
        print_fail "Output file not found. Airodump-ng may have failed"
    fi

else
    print_fail "Invalid Scan type. Please enter 1 or 2"
fi