#!/usr/bin/env python3
"""theme.py

Theme and colour configuration helper for the WSTT user interface.

This module loads UI theme settings from the project's configuration file,
determines the selected colour scheme, and provides a centralized `colour()`
function for applying consistent ANSI styling across all terminal output.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import json
import os
import re

COLOURS_DARK = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "header":  "\033[93m",
    "info":    "\033[96m",
    "success": "\033[92m",
    "warning": "\033[91m",
    "error":   "\033[91m",
    "prompt":  "\033[96m",
    "neutral": "\033[37m"
}

COLOURS_LIGHT = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "header":  "\033[94m",
    "info":    "\033[36m",
    "success": "\033[32m",
    "warning": "\033[31m",
    "error":   "\033[31m",
    "prompt":  "\033[36m",
    "neutral": "\033[90m"
}

COLOURS_HIGH_CONTRAST = {
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "header":  "\033[95m",
    "info":    "\033[94m",
    "success": "\033[92m",
    "warning": "\033[91m",
    "error":   "\033[41m\033[97m",
    "prompt":  "\033[96m",
    "neutral": "\033[93m"
}

COLOURS_MONOCHROME = {
    "reset":   "",
    "bold":    "",
    "header":  "",
    "info":    "",
    "success": "",
    "warning": "",
    "error":   "",
    "prompt":  "",
    "neutral": ""
}

THEMES = {
    "dark": COLOURS_DARK,
    "light": COLOURS_LIGHT,
    "high-contrast": COLOURS_HIGH_CONTRAST,
    "monochrome": COLOURS_MONOCHROME,
}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")

try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        THEME_MODE = config.get("ui", {}).get("theme_mode", "dark").lower()
        overrides = config.get("ui", {}).get("colours", {})
except (FileNotFoundError, json.JSONDecodeError, KeyError):
    THEME_MODE = "dark"
    overrides = {}

# Select the base theme, defaulting to dark if the configured theme is invalid.
COLOURS = THEMES.get(THEME_MODE, COLOURS_DARK).copy()

# Apply any user-defined colour overrides from the configuration.
for key, value in overrides.items():
    ansi_code = re.sub(r"\\033", "\033", value)
    if key in COLOURS:
        COLOURS[key] = ansi_code

def colour(text, style):
    """
    Apply ANSI styling to a given text string using the specified style key.

    Args:
        text (str): The string to be styled for CLI display.
        style (str): A style identifier such as 'header', 'success', 'warning', etc.
                     These map to ANSI codes defined by the active theme.

    Returns:
        str: The styled string wrapped in the selected ANSI codes and reset sequence.
    """
    return f"{COLOURS.get(style, '')}{text}{COLOURS.get('reset', '')}"

__all__ = ["colour", "COLOURS", "THEME_MODE"]