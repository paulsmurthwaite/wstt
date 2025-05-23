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
source "$CONFIG_DIR/capture.conf"

# ─── Helpers ───
source "$HELPERS_DIR/fn_print.sh"
source "$HELPERS_DIR/fn_mode.sh"

# ─── Output File ───
OUTPUT_FILE="$OUTPUT_DIR/captures/wstt_capture-$FILE_BASE.pcap"

# Input Capture type
while true; do
    print_prompt "Capture Type: [1] Full [2] Filtered: "
    read -r CAP_TYPE

    if [[ "$CAP_TYPE" == "1" || "$CAP_TYPE" == "2" ]]; then
        break
    else
        print_fail "Invalid selection. Please enter 1 or 2"
    fi
done

# Full capture
if [ "$CAP_TYPE" = "1" ]; then

    # Input mode
    while true; do
        print_prompt "Mode: [1] Duration [2] Packets: "
        read -r CAP_MODE

    if [[ "$CAP_MODE" == "1" || "$CAP_MODE" == "2" ]]; then
        break
    else
        print_fail "Invalid selection. Please enter 1 or 2"
    fi
    done

    # Selection handler
    if [ "$CAP_MODE" = "1" ]; then
        while true; do
            print_prompt "Duration (seconds) [default]: ${DEFAULT_CAPTURE_DURATION}]: "
            read -r DURATION

            DURATION="${DURATION:-$DEFAULT_CAPTURE_DURATION}"
            
            if [[ "$DURATION" =~ ^[0-9]+$ ]]; then
                break
            else
                print_fail "Invalid input. Enter a numeric value (seconds)"
            fi
        done

        # Check mode
        ensure_monitor_mode

        # Run capture
        print_blank
        print_action "Starting capture"
        sudo timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Duration=$DURATION seconds"

    elif [ "$CAP_MODE" = "2" ]; then
         while true; do
            print_prompt "Packets [default]: ${DEFAULT_CAPTURE_PACKETS}]: "
            read -r MAX_PACKETS

            MAX_PACKETS="${MAX_PACKETS:-$DEFAULT_CAPTURE_PACKETS}"
            
            if [[ "$MAX_PACKETS" =~ ^[0-9]+$ ]]; then
                break
            else
                print_fail "Invalid input. Enter a numeric value"
            fi
        done  

        # Check mode
        ensure_monitor_mode

        # Run capture
        print_blank
        print_action "Starting capture"
        sudo tcpdump -i "$INTERFACE" -c "$MAX_PACKETS" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Duration=$MAX_PACKETS packets"

    else
        print_fail "Invalid option. Please enter 1 or 2."
        exit 1
    fi

#  Filtered capture
elif [ "$CAP_TYPE" = "2" ]; then

    # BSSID
    while true; do
        print_prompt "BSSID (target AP): "
        read -r BSSID

        if [[ "$BSSID" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
            break
        else
            print_fail "Invalid BSSID format. Expected XX:XX:XX:XX:XX:XX"
        fi
    done

    # Channel
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

    # Check mode
    ensure_monitor_mode

    # Set channel
    print_blank
    print_action "Setting channel"
    sudo iw dev "$INTERFACE" set channel "$CHANNEL"
    CURRENT_CHANNEL=$(iw dev "$INTERFACE" info | awk '/channel/ {print $2}')
    print_info "Capture filter: BSSID=$BSSID, Channel=$CURRENT_CHANNEL"
    print_blank

    # Mode
    while true; do
        print_prompt "Mode: [1] Duration [2] Packets: "
        read -r CAP_MODE

    if [[ "$CAP_MODE" == "1" || "$CAP_MODE" == "2" ]]; then
        break
    else
        print_fail "Invalid selection. Please enter 1 or 2"
    fi
    done

    # Selection handler
    if [ "$CAP_MODE" = "1" ]; then
        while true; do
            print_prompt "Duration (seconds) [default]: ${DEFAULT_FILTERED_CAPTURE_DURATION}]: "
            read -r DURATION

            DURATION="${DURATION:-$DEFAULT_FILTERED_CAPTURE_DURATION}"
            
            if [[ "$DURATION" =~ ^[0-9]+$ ]]; then
                break
            else
                print_fail "Invalid input. Enter a numeric value (seconds)"
            fi
        done

        # Run capture
        print_blank
        print_action "Starting capture"
        sudo timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="BSSID=$BSSID | Channel=$CURRENT_CHANNEL | Duration=$DURATION seconds"

    elif [ "$CAP_MODE" = "2" ]; then
        while true; do
            print_prompt "Packets [default]: ${DEFAULT_FILTERED_CAPTURE_PACKETS}]: "
            read -r MAX_PACKETS

            MAX_PACKETS="${MAX_PACKETS:-$DEFAULT_FILTERED_CAPTURE_PACKETS}"
            
            if [[ "$MAX_PACKETS" =~ ^[0-9]+$ ]]; then
                break
            else
                print_fail "Invalid input. Enter a numeric value"
            fi
        done  

        # Run capture
        print_blank
        print_action "Starting capture"
        sudo tcpdump -i "$INTERFACE" -c "$MAX_PACKETS" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="BSSID=$BSSID | Channel=$CURRENT_CHANNEL | Packets=$MAX_PACKETS"

    else
        print_fail "Invalid Capture mode. Please enter 1 or 2."
    fi

else
    print_fail "Invalid Capture type. Please enter 1 or 2."
fi

# Set Managed mode
ensure_managed_mode

# File output
print_blank
print_success "Capture complete"
print_info "Capture parameters : $OUTPUT_PARAMS"
print_info "Output file        : $OUTPUT_FILE"