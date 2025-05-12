#!/bin/bash

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/load_env.sh"

./interface-down.sh
echo "[INFO] Setting Monitor mode on interface $INTERFACE ..."
sudo iw dev $INTERFACE set type monitor
./interface-up.sh

# What mode is the interface in
MODE=$(iw dev "$INTERFACE" info | awk '/type/ {print $2}')

if [ -n "$MODE" ]; then
    echo "[INFO] Interface $INTERFACE is in '$MODE' mode."
else
    echo "[WARN] Could not determine mode for interface $INTERFACE."
fi
