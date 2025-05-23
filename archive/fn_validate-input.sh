#!/bin/bash

validate_bssid() {
    local bssid="$1"

    if [ -z "$bssid" ]; then
        print_fail "BSSID cannot be empty."
        exit 1
    fi

    if ! [[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
        print_fail "Invalid BSSID format. Expected XX:XX:XX:XX:XX:XX"
        exit 1
    fi
}

validate_channel() {
    local channel="$1"

    if [ -z "$channel" ]; then
        print_fail "Channel cannot be empty."
        exit 1
    fi

    if ! [[ "$channel" =~ ^[0-9]+$ ]]; then
        print_fail "Channel must be numeric."
        exit 1
    fi

    # Convert comma-separated channel lists to space-separated
    local valid_channels_24="${CHANNELS_24GHZ_UK//,/ }"
    local valid_channels_5="${CHANNELS_5GHZ_UK//,/ }"
    local all_valid_channels="$valid_channels_24 $valid_channels_5"

    if ! [[ $all_valid_channels =~ (^|[[:space:]])$channel($|[[:space:]]) ]]; then
        print_fail "Channel $channel is not UK legal (2.4GHz or 5GHz safe set)."
        exit 1
    fi
}


validate_packet_count() {
    local count="$1"
    if [ -z "$count" ]; then
        print_fail "Packet count cannot be empty."
        exit 1
    fi
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
        print_fail "Packet count must be numeric."
        exit 1
    fi
}

validate_pcap_file() {
    local file="$1"
    if [ -z "$file" ]; then
        print_fail "No capture file specified."
        return 1
    elif [ ! -f "$file" ]; then
        print_fail "Capture file not found: $file"
        return 1
    elif [[ "$file" != *.pcap ]]; then
        print_fail "File does not have .pcap extension: $file"
        return 1
    fi
    return 0
}

select_pcap_file() {
    # Get pcap files
    local selected_file
    shopt -s nullglob
    local files=("$CAP_DIR"/*.pcap)
    shopt -u nullglob

    # Check file qty
    local num_files=${#files[@]}

    # No capture files
    if [ "$num_files" -eq 0 ]; then
        print_fail "No .pcap files found in $CAP_DIR" >&2
        return 1

    # Single capture file
    elif [ "$num_files" -eq 1 ]; then
        selected_file="${files[0]}"
        echo "" >&2
        print_info "Capture file found → $(basename "$selected_file")" >&2

    # Multiple capture files
    else
        echo "" >&2
        echo "[ Capture Files ]" >&2
        print_prompt "Select capture file:" >&2
        for i in "${!files[@]}"; do
            echo "    [$((i+1))] $(basename "${files[$i]}")" >&2
        done
        
        read -rp "    → " index

        if ! [[ "$index" =~ ^[0-9]+$ ]] || [ "$index" -lt 1 ] || [ "$index" -gt "$num_files" ]; then
            print_fail "Invalid selection." >&2
            return 1
        fi

        selected_file="${files[$((index-1))]}"
    fi

    echo "$selected_file"
    return 0
}

validate_csv_file() {
    local file="$1"
    if [ -z "$file" ]; then
        print_fail "No scan file specified." >&2
        return 1
    elif [ ! -f "$file" ]; then
        print_fail "Scan file not found: $file" >&2
        return 1
    elif [[ "$file" != *.csv ]]; then
        print_fail "File does not have .csv extension: $file" >&2
        return 1
    fi
    return 0
}

select_csv_file() {
    # Get csv files
    local selected_file
    shopt -s nullglob
    local files=("$SCN_DIR"/*.csv)
    shopt -u nullglob

    # Check file qty
    local num_files=${#files[@]}

    # No scan files
    if [ "$num_files" -eq 0 ]; then
        print_fail "No .csv scan files found in $SCN_DIR" >&2
        return 1

    # Single scan file
    elif [ "$num_files" -eq 1 ]; then
        selected_file="${files[0]}"
        echo "" >&2
        print_info "Scan file found → $(basename "$selected_file")" >&2

    # Multiple scan files
    else
        echo "" >&2
        echo "[ Scan Files ]" >&2
        print_prompt "Select scan file:" >&2
        for i in "${!files[@]}"; do
            echo "    [$((i+1))] $(basename "${files[$i]}")" >&2
        done

        read -rp "    → " index

        if ! [[ "$index" =~ ^[0-9]+$ ]] || [ "$index" -lt 1 ] || [ "$index" -gt "$num_files" ]; then
            print_fail "Invalid selection." >&2
            return 1
        fi
        
        selected_file="${files[$((index-1))]}"
    fi

    echo "$selected_file"
    return 0
}