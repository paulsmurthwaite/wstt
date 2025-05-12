#!/bin/bash

# Load config
source ./config/config.sh

echo ""
echo "[ WSTT Path Configuration Check ]"
echo ""

# Display key config variables
echo "[+] PROJECT_ROOT   : $PROJECT_ROOT"
echo "[+] SCRIPT_DIR   : $SCRIPT_DIR"
echo ""
echo "[+] SCAN_DIR: $SCN_DIR"
echo "[+] CAPTURE_DIR   : $CAP_DIR"
echo ""
echo "[+] TIMESTAMP   : $TIMESTAMP"
echo "[+] FILE_BASE   : $FILE_BASE"
echo ""
echo "[+] CHANNELS_24GHZ_UK   : $CHANNELS_24GHZ_UK"
echo "[+] CHANNELS_5GHZ_UK   : $CHANNELS_5GHZ_UK"
echo "[+] CHANNELS_5GHZ_UK   : $CHANNELS_5GHZ_UK"
echo "[+] INTERFACE   : $INTERFACE"
echo ""
echo "[+] DEFAULT_SCAN_DURATION   : $DEFAULT_SCAN_DURATION"
echo "[+] DEFAULT_CAPTURE_DURATION   : $DEFAULT_CAPTURE_DURATION"
echo "[+] DEFAULT_CAPTURE_PACKETS   : $DEFAULT_CAPTURE_PACKETS"
echo "[+] DEFAULT_FILTERED_CAPTURE_DURATION   : $DEFAULT_FILTERED_CAPTURE_DURATION"
echo "[+] DEFAULT_FILTERED_CAPTURE_PACKETS   : $DEFAULT_FILTERED_CAPTURE_PACKETS"
echo ""

