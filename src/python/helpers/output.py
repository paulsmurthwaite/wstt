#!/usr/bin/env python3

import os
import sys
from datetime import datetime
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

# --- Divider Line ---
def print_line(char='-', length=50):
    """Prints a divider line."""
    print(colour(char * length, "neutral"))

# ─── File Logging ───
LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))

class Logger:
    """A simple logger class that writes to both terminal and a file."""
    def __init__(self, terminal, logfile):
        self.terminal = terminal
        self.logfile = logfile

    def write(self, message):
        self.terminal.write(message)
        self.logfile.write(message)

    def flush(self):
        self.terminal.flush()
        self.logfile.flush()

def setup_file_logging(log_prefix):
    """Redirects stdout to a logger that writes to both screen and file."""
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    log_filename = os.path.join(LOG_DIR, f"wstt_{log_prefix}-{timestamp}.log")

    log_file = open(log_filename, 'w', encoding='utf-8')
    sys.stdout = Logger(sys.stdout, log_file)

    print_success(f"Logging output to {os.path.basename(log_filename)}")
    print_blank()

__all__ = ["print_success", "print_warning", "print_error", "print_action", "print_info", "print_waiting", "print_prompt", "print_blank", "print_none", "ui_header", "ui_clear_screen", "print_line", "setup_file_logging"]