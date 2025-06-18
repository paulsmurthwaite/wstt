#!/usr/bin/env python3

import json
import os
import re

# ─── Default Theme Definitions ───
COLOURS_DARK = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "header": "\033[93m",
    "info":   "\033[96m",
    "success": "\033[92m",
    "warning": "\033[91m",
    "neutral": "\033[90m"
}

COLOURS_LIGHT = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "header": "\033[94m",
    "info":   "\033[36m",
    "success": "\033[32m",
    "warning": "\033[31m",
    "neutral": "\033[30m"
}

COLOURS_HIGH_CONTRAST = {
    "reset":  "\033[0m",
    "bold":   "\033[1m",
    "header": "\033[97m",
    "info":   "\033[96m",
    "success": "\033[92m",
    "warning": "\033[91m",
    "neutral": "\033[97m"
}

COLOURS_MONOCHROME = {
    "reset":  "",
    "bold":   "",
    "header": "",
    "info":   "",
    "success": "",
    "warning": "",
    "neutral": ""
}

# ─── Load Configuration ───
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")

# Default theme fallback
THEME_MODE = "dark"
COLOURS = COLOURS_DARK.copy()

try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        
        # Load theme mode
        THEME_MODE = config.get("ui", {}).get("theme_mode", "dark").lower()
        
        if THEME_MODE == "light":
            COLOURS = COLOURS_LIGHT.copy()
        elif THEME_MODE == "high-contrast":
            COLOURS = COLOURS_HIGH_CONTRAST.copy()
        elif THEME_MODE == "monochrome":
            COLOURS = COLOURS_MONOCHROME.copy()
        else:
            COLOURS = COLOURS_DARK.copy()  # Default fallback

        # Load optional colour overrides
        override = config.get("ui", {}).get("colours", {})
        for key, value in override.items():
            # Replace double-backslashes with actual escape codes
            ansi_code = re.sub(r"\\033", "\033", value)
            if key in COLOURS:
                COLOURS[key] = ansi_code

except Exception:
    # If config load fails, fall back to dark theme silently
    COLOURS = COLOURS_DARK.copy()

# ─── Apply Colour to Text ───
def colour(text, style):
    return f"{COLOURS.get(style, '')}{text}{COLOURS.get('reset', '')}"

# Optional export
__all__ = ["colour", "COLOURS", "THEME_MODE"]