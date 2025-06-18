#!/usr/bin/env python3

from helpers.theme import colour

# ─── Success Message ───
def print_success(message):
    print(f"{colour('[+]', 'success')} {message}")

# ─── Warning Message ───
def print_warning(message):
    print(f"{colour('[!]', 'warning')} {message}")

# ─── Error Message ───
def print_error(message):
    print(f"{colour('[x]', 'error')} {message}")

# ─── Action/Progress Message ───
def print_action(message):
    print(f"{colour('[>]', 'info')} {message}")

# ─── Informational Message ───
def print_info(message):
    print(f"{colour('[*]', 'info')} {message}")

# ─── Waiting Message ───
def print_waiting(message):
    print(f"{colour('[~]', 'info')} {message}")

# ─── Prompt Message ───
def print_prompt(message):
    print(f"{colour('[?]', 'prompt')} {message}", end='')

# ─── Blank Line ───
def print_blank():
    print()

__all__ = ["print_success", "print_warning", "print_error", "print_action", "print_info", "print_waiting", "print_prompt", "print_blank"]