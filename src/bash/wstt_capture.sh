#!/bin/bash

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/fn_load-env.sh"

# Parameters
OUTPUT_FILE="$CAP_DIR/wstt_capture-$FILE_BASE.pcap"

# Capture type
echo "[+] Capture Type:"
echo "    [1] Full"
echo "    [2] Filtered"
read -rp "    → " CAP_TYPE

# Full capture
if [ "$CAP_TYPE" = "1" ]; then

    # Input mode
    echo ""
    echo "[ Full Capture ]"
    echo ""
    echo "[+] Mode:"
    echo "    [1] Duration"
    echo "    [2] Packets"
    read -rp "    → " CAP_MODE

    # Selection handler
    if [ "$CAP_MODE" = "1" ]; then
        echo ""
        echo "[ Full Capture (Duration) ]"
        echo ""
        echo "[+] Duration (seconds) [default]: ${DEFAULT_CAPTURE_DURATION}]: "
        read -rp "    → " DURATION
        DURATION="${DURATION:-$DEFAULT_CAPTURE_DURATION}"
        validate_duration "$DURATION"

        # Run capture
        printf "\n"
        echo "[INFO] Full Capture for $DURATION seconds..."
        sudo timeout "$DURATION" \
            tcpdump -i "$INTERFACE" \
            -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Duration=$DURATION seconds"

    elif [ "$CAP_MODE" = "2" ]; then
        echo ""
        echo "[ Full Capture (Packets) ]"
        echo ""
        echo "[+] Packets [default]: ${DEFAULT_CAPTURE_PACKETS}]: "
        read -rp "    → " MAX_PACKETS
        MAX_PACKETS="${MAX_PACKETS:-$DEFAULT_CAPTURE_PACKETS}"
        validate_packet_count "$MAX_PACKETS"
        
        # Run capture
        echo ""
        echo "[INFO] Full capture of $MAX_PACKETS packets..."
        sudo tcpdump -i "$INTERFACE" \
            -c "$MAX_PACKETS" \
            -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="Duration=$MAX_PACKETS packets"

    else
        echo "[ERROR] Invalid option. Please enter 1 or 2."
        exit 1
    fi

#  Filtered capture
elif [ "$CAP_TYPE" = "2" ]; then

    # Filter parameters
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

    # Set channel
    sudo iw dev "$INTERFACE" set channel "$CHANNEL"
    CURRENT_CHANNEL=$(iw dev "$INTERFACE" info | awk '/channel/ {print $2}')
    echo ""
    echo "[INFO] Applying filter: BSSID=$BSSID, Channel=$CURRENT_CHANNEL"

    # Input mode
    echo ""
    echo "[ Capture Mode ]"
    echo ""
    echo "[+] Mode:"
    echo "    [1] Duration"
    echo "    [2] Packets"
    read -rp "    → " CAP_MODE

    # Selection handler
    if [ "$CAP_MODE" = "1" ]; then
        echo ""
        echo "[ Filtered Capture (Duration) ]"
        echo ""
        echo "[+] Duration (seconds) [default]: ${DEFAULT_FILTERED_CAPTURE_DURATION}]: "
        read -rp "    → " DURATION
        DURATION="${DURATION:-$DEFAULT_FILTERED_CAPTURE_DURATION}"
        validate_duration "$DURATION"

        # Run capture
        echo ""
        echo "[INFO] Filtered capture for $DURATION seconds..."
        echo ""
        sudo timeout "$DURATION" tcpdump -i "$INTERFACE" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="BSSID=$BSSID | Channel=$CURRENT_CHANNEL | Duration=$DURATION seconds"

    elif [ "$CAP_MODE" = "2" ]; then
        echo ""
        echo "[ Filtered Capture (Packets) ]"
        echo ""
        echo "[+] Packets [default]: ${DEFAULT_FILTERED_CAPTURE_PACKETS}]: "
        read -rp "    → " MAX_PACKETS
        MAX_PACKETS="${MAX_PACKETS:-$DEFAULT_FILTERED_CAPTURE_PACKETS}"
        validate_packet_count "$MAX_PACKETS"

        # Run capture
        echo ""
        echo "[INFO] Filtered capture of $MAX_PACKETS packets..."
        echo ""
        sudo tcpdump -i "$INTERFACE" -c "$MAX_PACKETS" -w "$OUTPUT_FILE"
        OUTPUT_PARAMS="BSSID=$BSSID | Channel=$CURRENT_CHANNEL | Packets=$MAX_PACKETS"

    else
        echo "[ERROR] Invalid Capture mode. Please enter 1 or 2."
        exit 1
    fi

else
    echo "[ERROR] Invalid Capture type. Please enter 1 or 2."
    exit 1
fi

# File output
printf "\n[INFO] Capture complete.\n"
echo "[INFO] Applied Parameters: $OUTPUT_PARAMS"
echo "[INFO] Output saved to: $OUTPUT_FILE"