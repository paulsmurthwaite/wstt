#!/usr/bin/env python3
"""output.py

Provides a suite of functions for generating consistent, themed terminal output.

This module centralizes all user-facing print operations, from simple styled
messages (success, error, warning) to more complex UI elements like headers
and dividers. It also includes a logging utility to redirect stdout to both
the terminal and a timestamped log file for auditing and debugging purposes.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import os
import sys
from datetime import datetime

# ─── Local Modules ───
from helpers.theme import colour

# ─── UI Header ───
def ui_header(title="Wireless Security Testing Toolkit"):
    """Displays a styled section header."""
    styled = colour(colour(f"[ {title} ]", "bold"), "header")
    print(styled)

# ─── UI Clear Screen ───
def ui_clear_screen():
    """Clears the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")

# ─── Success Message ───
def print_success(message):
    """Prints a success message, styled with a '[+]' prefix."""
    print(f"{colour('[+]', 'success')} {message}")

# ─── Warning Message ───
def print_warning(message):
    """Prints a warning message, styled with a '[!]' prefix."""
    print(f"{colour('[!]', 'warning')} {message}")

# ─── Error Message ───
def print_error(message):
    """Prints an error message, styled with a '[x]' prefix."""
    print(f"{colour('[x]', 'error')} {message}")

# ─── Action/Progress Message ───
def print_action(message):
    """Prints an action or progress message, styled with a '[>]' prefix."""
    print(f"{colour('[>]', 'info')} {message}")

# ─── Informational Message ───
def print_info(message):
    """Prints an informational message, styled with a '[*]' prefix."""
    print(f"{colour('[*]', 'info')} {message}")

# ─── Waiting Message ───
def print_waiting(message):
    """Prints a waiting message, styled with a '[~]' prefix."""
    print(f"{colour('[~]', 'info')} {message}")

# ─── Prompt Message ───
def print_prompt(message):
    """Prints a user prompt message without a newline."""
    print(f"{colour('[?]', 'prompt')} {message}", end='')

# ─── No formatting Message ───
def print_none(message):
    """Prints a message with no styling or prefix."""
    print(f"{message}")

# ─── Blank Line ───
def print_blank():
    """Prints a blank line."""
    print()

# --- Divider Line ---
def print_line(char='-', length=50):
    """Prints a styled divider line.

    Args:
        char (str): The character to repeat for the line.
        length (int): The length of the line.
    """
    print(colour(char * length, "neutral"))

__all__ = ["print_success", "print_warning", "print_error", "print_action", "print_info", "print_waiting", "print_prompt", "print_blank", "print_none", "ui_header", "ui_clear_screen", "print_line"]