#!/bin/bash

# Load helpers
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/fn_load-env.sh"

print_blank
echo "[ WSTT Path Configuration Check ]"
print_blank

# Display key config variables
print_info "PROJECT_ROOT   : $PROJECT_ROOT"
print_info "SCRIPT_DIR     : $SCRIPT_DIR"
print_blank
print_info "SCAN_DIR       : $SCN_DIR"
print_info "CAPTURE_DIR    : $CAP_DIR"
print_blank
print_info "TIMESTAMP      : $TIMESTAMP"
print_info "FILE_BASE      : $FILE_BASE"
print_blank
print_info "INTERFACE          : $INTERFACE"
print_info "CHANNELS_24GHZ_UK  : $CHANNELS_24GHZ_UK"
print_info "CHANNELS_5GHZ_UK   : $CHANNELS_5GHZ_UK"
print_blank
print_info "DEFAULT_SCAN_DURATION               : $DEFAULT_SCAN_DURATION"
print_info "DEFAULT_CAPTURE_DURATION            : $DEFAULT_CAPTURE_DURATION"
print_info "DEFAULT_CAPTURE_PACKETS             : $DEFAULT_CAPTURE_PACKETS"
print_info "DEFAULT_FILTERED_CAPTURE_DURATION   : $DEFAULT_FILTERED_CAPTURE_DURATION"
print_info "DEFAULT_FILTERED_CAPTURE_PACKETS    : $DEFAULT_FILTERED_CAPTURE_PACKETS"
print_blank