#!/bin/bash

source ./config.sh

echo "[INFO] Bringing interface $INTERFACE down..."
sudo ip link set $INTERFACE down
sleep 3

LINK_OUTPUT=$(ip link show "$INTERFACE")  # Inspect the interface status
MODE_LINE=$(echo "$LINK_OUTPUT" | grep "UP")  # Extract the UP indicator

# Is True
if [ -n "$MODE_LINE" ]; then
    echo "[INFO] Interface $INTERFACE is UP."
else
    echo "[INFO] Interface $INTERFACE is DOWN."
fi