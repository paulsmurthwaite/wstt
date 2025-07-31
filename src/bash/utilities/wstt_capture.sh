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
OUTPUT_FILE="$OUTPUT_DIR/captures/wstt_capture-$FILE_BASE.pcap"

# --- Argument Parsing ---
CAPTURE_MODE=$1

if [[ -z "$CAPTURE_MODE" ]]; then
    print_fail "No capture mode specified. Use --full, --channel, or --bssid."
    exit 1
fi

# --- Capture Logic ---
case "$CAPTURE_MODE" in
    --full)
        print_action "Loading default capture parameters:"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting full capture (all channels)..."
        sudo timeout "$DEFAULT_DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Mode=Full | Duration=$DEFAULT_DURATION seconds"
        ;;
    --channel)
        print_action "Loading default capture parameters:"
        print_info "Channel: $DEFAULT_CHANNEL"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting filtered capture by channel..."
        print_action "Setting interface to channel $DEFAULT_CHANNEL..."
        sudo iw dev "$INTERFACE" set channel "$DEFAULT_CHANNEL"
        CURRENT_CHANNEL=$(iw dev "$INTERFACE" info | awk '/channel/ {print $2}')
        print_success "Interface is now on channel $CURRENT_CHANNEL."
        print_blank
        sudo timeout "$DEFAULT_DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Mode=Channel | Channel=$CURRENT_CHANNEL | Duration=$DEFAULT_DURATION seconds"
        ;;
    --bssid)
        print_action "Loading default capture parameters:"
        print_info "BSSID:   $DEFAULT_BSSID"
        print_info "Channel: $DEFAULT_CHANNEL"
        print_info "Duration: $DEFAULT_DURATION seconds"
        confirmation

        ensure_monitor_mode
        print_blank

        print_action "Starting filtered capture by BSSID and channel..."
        print_action "Setting interface to channel $DEFAULT_CHANNEL..."
        sudo iw dev "$INTERFACE" set channel "$DEFAULT_CHANNEL"
        CURRENT_CHANNEL=$(iw dev "$INTERFACE" info | awk '/channel/ {print $2}')
        print_success "Interface is now on channel $CURRENT_CHANNEL."
        print_blank
        # Using 'wlan host' is a robust tcpdump filter for traffic to/from a BSSID
        sudo timeout "$DEFAULT_DURATION" tcpdump -i "$INTERFACE" "wlan host $DEFAULT_BSSID" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Mode=BSSID | BSSID=$DEFAULT_BSSID | Channel=$CURRENT_CHANNEL | Duration=$DEFAULT_DURATION seconds"
        ;;
    *)
        print_fail "Invalid capture mode: '$CAPTURE_MODE'. Use --full, --channel, or --bssid."
        exit 1
        ;;
esac

# --- Post-capture ---
# Set Managed mode
ensure_managed_mode

# File output
print_blank
print_success "Capture complete"
print_info "Capture parameters : $OUTPUT_PARAMS"
print_info "Output file        : $OUTPUT_FILE"