#!/bin/bash

# ─── Success Message ───
print_success() {
    echo "[+] $1"
}

# ─── Warning Message ───
print_warn() {
    echo "[!] $1"
}

# ─── Error Message ───
print_fail() {
    echo "[x] $1"
}

# ─── Action/Progress Message ───
print_action() {
    echo "[>] $1"
}

# ─── Informational Message ───
print_info() {
    echo "[*] $1"
}

# ─── Waiting Message ───
print_waiting() {
    echo "[~] $1"
}

# ─── Prompt Message ───
print_prompt() {
    echo -n "[?] $1"
}

# ─── Blank Line ───
print_blank() {
    echo ""
}

print_none() {
    echo "$1"
}

print_section() {
    echo -e "\033[1m[ $1 ]\033[0m"
}