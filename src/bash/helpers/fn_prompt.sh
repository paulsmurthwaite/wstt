#!/bin/bash

confirmation() {
    print_blank
    print_prompt "Proceed [y/N]: "
    read -r READY
    # Exit with a non-zero status code to indicate user cancellation,
    # distinguishing it from a successful script completion (exit 0).
    [[ "$READY" != "y" && "$READY" != "Y" ]] && exit 1
    print_blank
}