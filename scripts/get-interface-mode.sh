#!/bin/bash

source ./config.sh

# What mode is the interface in
MODE=$(iw dev "$INTERFACE" info | awk '/type/ {print $2}')

if [ -n "$MODE" ]; then
    echo "[INFO] Interface $INTERFACE is in '$MODE' mode."
else
    echo "[WARN] Could not determine mode for interface $INTERFACE."
fi