#!/bin/bash

# Load environment
source "$(dirname "${BASH_SOURCE[0]}")/fn_load-env.sh"

# Interface soft reset
./set-interface-down.sh
./set-interface-up.sh

# Check interface state
./get-current-interface.sh