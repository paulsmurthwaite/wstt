#!/bin/bash

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/load_env.sh"

ip link show $INTERFACE  # show specific interface