#!/bin/bash

# Define path to bash/ directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"  # /src/bash

# Load core configuration and helpers from within /bash/
source "$SCRIPT_DIR/config/config.sh"
source "$SCRIPT_DIR/helpers/validate_input.sh"
