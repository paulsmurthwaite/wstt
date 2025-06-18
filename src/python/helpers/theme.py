"""
Theme and colour configuration helper for the WSTT user interface.

This module loads UI theme settings from config/config.json, determines the selected
colour scheme (e.g. dark, light, high-contrast, monochrome), and provides a centralised
colour(text, style) function for applying consistent ANSI styling across CLI output.

The active theme is set via the "theme_mode" field in the config file. Optional
colour overrides can be defined using ANSI escape codes under the "colours" field.
"""

import json
import os
import re

print("[theme.py] LOADED!")

# ─── Default Theme Definitions ───
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

# ─── Configuration Loader ───
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
THEME_MODE = "dark"
COLOURS = COLOURS_DARK.copy()

try:
    with open(CONFIG_PATH, "r") as f:
        config = json.load(f)
        THEME_MODE = config.get("ui", {}).get("theme_mode", "dark").lower()
        override = config.get("ui", {}).get("colours", {})
except Exception:
    override = {}

# ─── Theme Mapping ───
if THEME_MODE == "light":
    COLOURS = COLOURS_LIGHT.copy()
elif THEME_MODE == "high-contrast":
    COLOURS = COLOURS_HIGH_CONTRAST.copy()
elif THEME_MODE == "monochrome":
    COLOURS = COLOURS_MONOCHROME.copy()
else:
    COLOURS = COLOURS_DARK.copy()

# ─── Apply Colour Overrides ───
for key, value in override.items():
    ansi_code = re.sub(r"\\033", "\033", value)
    if key in COLOURS:
        COLOURS[key] = ansi_code

# ─── DEBUG Printout ───
if os.getenv("WSTT_DEBUG_THEME") == "1":
    print(f"[DEBUG] THEME_MODE = {THEME_MODE}")
    print(f"[DEBUG] COLOURS['header'] = {repr(COLOURS['header'])}")

# ─── Colour Function ───
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
