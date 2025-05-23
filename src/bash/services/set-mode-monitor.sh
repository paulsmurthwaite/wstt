#!/bin/bash

# ─── Paths ───
BASH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$BASH_DIR/config"
HELPERS_DIR="$BASH_DIR/helpers"
SERVICES_DIR="$BASH_DIR/services"

# ─── Configs ───
source "$CONFIG_DIR/global.conf"

# ─── Helpers ───
source "$HELPERS_DIR/fn_print.sh"

# ─── Change mode ───
bash "$SERVICES_DIR/set-interface-down.sh"  # Interface down
print_action "Setting interface mode MONITOR"
sudo iw dev $INTERFACE set type monitor
bash "$SERVICES_DIR/set-interface-up.sh"  # Interface up