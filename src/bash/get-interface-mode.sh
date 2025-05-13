#!/bin/bash

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/fn_load-env.sh"

# Read interface mode
MODE=$(iw dev "$INTERFACE" info | awk '/type/ {print $2}')

# Display interface mode
if [ -n "$MODE" ]; then
    echo "[INFO] Interface $INTERFACE is in '$MODE' mode."
else
    echo "[WARN] Could not determine mode for interface $INTERFACE."
fi