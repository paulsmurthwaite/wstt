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

# ─── Helpers ───
source "$HELPERS_DIR/fn_print.sh"
source "$HELPERS_DIR/fn_mode.sh"
source "$HELPERS_DIR/fn_prompt.sh"

# ─── Output File ───
FILE_BASE=$(date +%Y%m%d-%H%M%S)

# --- Argument Parsing ---
SCAN_MODE=$1

if [[ -z "$SCAN_MODE" ]]; then
    print_fail "No scan mode specified. Use --full, --channel, or --bssid."
    exit 1
fi

# --- Scan Logic ---
case "$SCAN_MODE" in
    --full)
        OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-full-$FILE_BASE"
        print_action "Loading default scan parameters:"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting full scan (all channels)..."
        sudo timeout "$DEFAULT_DURATION" airodump-ng "$INTERFACE" --write "$OUTPUT_FILE" --output-format csv
        OUTPUT_PARAMS="Mode=Full | Duration=$DEFAULT_DURATION seconds"
        ;;
    --channel)
        OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-channel-$FILE_BASE"
        print_action "Loading default scan parameters:"
        print_info "Channel: $DEFAULT_CHANNEL"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting filtered scan by channel..."
        sudo timeout "$DEFAULT_DURATION" airodump-ng "$INTERFACE" --channel "$DEFAULT_CHANNEL" --write "$OUTPUT_FILE" --output-format csv
        OUTPUT_PARAMS="Mode=Channel | Channel=$DEFAULT_CHANNEL | Duration=$DEFAULT_DURATION seconds"
        ;;
    --bssid)
        OUTPUT_FILE="$OUTPUT_DIR/scans/wstt_scan-bssid-$FILE_BASE"
        print_action "Loading default scan parameters:"
        print_info "BSSID:   $DEFAULT_BSSID"
        print_info "Channel: $DEFAULT_CHANNEL"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting filtered scan by BSSID and channel..."
        sudo timeout "$DEFAULT_DURATION" airodump-ng "$INTERFACE" --bssid "$DEFAULT_BSSID" --channel "$DEFAULT_CHANNEL" --write "$OUTPUT_FILE" --output-format csv
        OUTPUT_PARAMS="Mode=BSSID | BSSID=$DEFAULT_BSSID | Channel=$DEFAULT_CHANNEL | Duration=$DEFAULT_DURATION seconds"
        ;;
    *)
        print_fail "Invalid scan mode: '$SCAN_MODE'. Use --full, --channel, or --bssid."
        exit 1
        ;;
esac

# --- Post-scan ---
# airodump-ng appends '-01.csv' to the filename
if [ -f "${OUTPUT_FILE}-01.csv" ]; then
    mv "${OUTPUT_FILE}-01.csv" "${OUTPUT_FILE}.csv"
fi

# Set Managed mode
ensure_managed_mode

# File output
print_blank
if [ -f "${OUTPUT_FILE}.csv" ]; then
    print_success "Scan complete"
    print_info "Scan parameters : $OUTPUT_PARAMS"
    print_info "Output file     : ${OUTPUT_FILE}.csv"
else
    print_fail "Output file not found. Airodump-ng may have failed or been cancelled."
fi