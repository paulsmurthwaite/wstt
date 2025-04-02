#!/bin/bash

source ./config.sh

# Read interface driver
DRIVER=$(basename "$(readlink /sys/class/net/$INTERFACE/device/driver)")

# Remove interface driver
echo "[INFO] Unloading interface $INTERFACE driver $DRIVER ..."
sudo rmmod $DRIVER

# Reload interface driver
echo "[INFO] Reloading interface $INTERFACE ..."
sudo modprobe $DRIVER
sleep 5

# Check interface state
LINK_OUTPUT=$(ip link show "$INTERFACE")  # Inspect the interface status
MODE_LINE=$(echo "$LINK_OUTPUT" | grep "UP")  # Extract the UP indicator

# Is True
if [ -n "$MODE_LINE" ]; then
    echo "[INFO] Interface $INTERFACE is UP."
else
    echo "[INFO] Interface $INTERFACE is DOWN."
fi
