#!/bin/bash

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/fn_load-env.sh"

# Set interface down
./set-interface-down.sh

# Change mode
echo "[INFO] Setting Monitor mode on interface $INTERFACE ..."
sudo iw dev $INTERFACE set type monitor

# Bring interface up
./set-interface-up.sh

# Read interface mode
./get-interface-mode.sh