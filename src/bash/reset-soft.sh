#!/bin/bash

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/load_env.sh"

# Interface soft reset
./interface-down.sh
./interface-up.sh
