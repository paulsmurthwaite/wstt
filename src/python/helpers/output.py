#!/usr/bin/env python3

import os
from helpers.theme import colour

# ─── UI Header ───
def ui_header(title="Wireless Security Testing Toolkit"):
    """
    Display section header.
    """
    styled = colour(colour(f"[ {title} ]", "bold"), "header")
    print(styled)

# ─── UI Clear Screen ───
def ui_clear_screen():
    """
    Clear terminal screen.
    """
    os.system("cls" if os.name == "nt" else "clear")

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

# ─── No formatting Message ───
def print_none(message):
    print(f"{message}")

# ─── Blank Line ───
def print_blank():
    print()

__all__ = ["print_success", "print_warning", "print_error", "print_action", "print_info", "print_waiting", "print_prompt", "print_blank", "print_none", "ui_header", "ui_clear_screen"]