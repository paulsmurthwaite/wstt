#!/bin/bash

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/fn_load-env.sh"

# Show current interface
ip link show $INTERFACE

# Check interface state
LINK_OUTPUT=$(ip link show "$INTERFACE")  # Inspect the interface status
MODE_LINE=$(echo "$LINK_OUTPUT" | grep "UP")  # Extract the UP indicator

# Display interface state
if [ -n "$MODE_LINE" ]; then
    echo "[INFO] Interface $INTERFACE is UP."
else
    echo "[INFO] Interface $INTERFACE is DOWN."
fi