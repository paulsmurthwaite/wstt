#!/usr/bin/env python3
"""ui.py

Provides all user interface rendering functions for the WSTT.

This module is responsible for drawing all menus, headers, banners, and other
UI elements to the console. It consolidates presentation logic, making the
application's look and feel easy to manage from a single location.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import pyfiglet

# ─── Local Modules ───
from helpers.theme import colour
from helpers.output import (
    print_blank,
    print_prompt,
    print_warning,
    ui_clear_screen,
    ui_header,
)
from helpers.system import get_interface_details


# ─── UI Components ───
def ui_banner():
    """Display ASCII banner."""
    ascii_banner = pyfiglet.figlet_format("WSTT", font="ansi_shadow")
    print(colour(ascii_banner, "header"))

def ui_divider():
    """Display divider."""
    print(colour("-----------------------------------", "neutral"))
    print_blank()

def ui_subtitle():
    """Display combined subtitle."""
    ui_divider()
    print_interface_status()
    ui_divider()

def ui_standard_header(menu_title=None):
    """
    Render standard UI header block: banner, main title, subtitle.

    Args:
        menu_title (str, optional): A title for the current menu to display
                                    below the main header. Defaults to None.
    """
    ui_banner()
    ui_header()
    print_blank()
    ui_subtitle()

    if menu_title:
        ui_header(menu_title)
        print_blank()

def ui_pause_on_invalid():
    """Display invalid input message and pause."""
    print_blank()
    print_warning("Invalid option. Please try again.")
    print_prompt("Press Enter to continue")
    input()

def print_interface_status():
    """Print the current interface, state, and mode."""
    interface, state_raw, mode_raw = get_interface_details()

    state = state_raw.title()
    mode = "AP" if mode_raw.lower() == "ap" else mode_raw.title()

    mode_colours = {
        "managed": "success",
        "monitor": "warning",
        "ap": "warning",
    }

    interface_display = colour(interface, "info")
    state_display = colour(state, "success" if state.lower() == "up" else "warning")
    mode_display = colour(mode, mode_colours.get(mode_raw.lower(), "reset"))

    print(f"[ Interface       ] {interface_display}")
    print(f"[ Interface State ] {state_display}")
    print(f"[ Interface Mode  ] {mode_display}")
    print_blank()


# ─── Menu Displays ───
def _display_generic_menu(title, items, exit_message="Return to Main Menu"):
    """A generic helper to display a standard menu screen."""
    ui_clear_screen()
    ui_standard_header(title)
    for item in items:
        print(item)
    print(f"\n[0] {exit_message}")


def display_main_menu():
    """Display main menu."""
    ui_clear_screen()
    ui_standard_header("Main Menu")

    ui_header("Acquisition")
    print("[1] Scan Wireless Traffic")
    print("[2] Capture Wireless Frames")
    print_blank()
    ui_header("Analysis")
    print("[3] Threat Detection")
    print_blank()
    ui_header("Services")
    print("[4] Service Control")
    print_blank()
    print("[5] Help | About")

    print("\n[0] Exit")

def display_scan_menu():
    """Display the scan submenu."""
    title = "Scan Wireless Traffic"
    items = [
        "[1] Full Scan (all channels)",
        "[2] Filtered Scan (by channel)",
        "[3] Filtered Scan (by BSSID & channel)",
    ]
    _display_generic_menu(title, items, "Return to Main Menu")

def display_capture_menu():
    """Display the capture submenu."""
    title = "Capture Wireless Frames"
    items = [
        "[1] Full Capture (all channels)",
        "[2] Filtered Capture (by channel)",
        "[3] Filtered Capture (by BSSID & channel)",
    ]
    _display_generic_menu(title, items, "Return to Main Menu")

def display_threat_detection_menu():
    """Display the threat detection submenu."""
    title = "Threat Detection Scenarios"
    items = [
        "[1]  T001 – Unencrypted Traffic Capture",
        "[2]  T002 – Probe Request Snooping",
        "[3]  T003 – SSID Harvesting",
        "[4]  T004 – Evil Twin Attack",
        "[5]  T005 – Open Rogue AP",
        "[6]  T006 – Misconfigured Access Point",
        "[7]  T007 – Deauthentication Flood",
        "[8]  T008 – Beacon Flood",
        "[9]  T009 – Authentication Flood",
        "[10] T014 – ARP Spoofing from Wireless Entry Point",
        "[11] T015 – Malicious Hotspot Auto-Connect",
        "[12] T016 – Directed Probe Response",
    ]
    _display_generic_menu(title, items)

def display_service_control_menu():
    """Display the service control submenu."""
    title = "Service Control"
    items = [
        "[1] Change Interface State",
        "[2] Change Interface Mode",
        "[3] Reset Interface",
    ]
    _display_generic_menu(title, items)

def display_interface_state_menu():
    """Display the interface state submenu."""
    title = "Set Interface State"
    items = ["[1] Set interface state DOWN", "[2] Set interface state UP"]
    _display_generic_menu(title, items, "Return to Service Control Menu")

def display_interface_mode_menu():
    """Display the interface mode submenu."""
    title = "Set Interface Mode"
    items = ["[1] Set interface mode MANAGED", "[2] Set interface mode MONITOR"]
    _display_generic_menu(title, items, "Return to Service Control Menu")

def display_interface_reset_menu():
    """Display the interface reset submenu."""
    title = "Reset Interface"
    items = [
        "[1] Perform Soft Reset (Interface Down/Up)",
        "[2] Perform Hard Reset (Unload/Reload)",
    ]
    _display_generic_menu(title, items, "Return to Service Control Menu")

def display_help_about_screen():
    """Display the Help/About screen and pause for user."""
    ui_clear_screen()
    ui_standard_header("Help | About")

    print("WSTT (Wireless Security Testing Toolkit) provides a menu-driven interface")
    print("to launch predefined wireless attack scenarios in a controlled")
    print("testing environment.  Each attack corresponds to a specific threat")
    print("profile and is executed using underlying Bash-based tools.")
    print_blank()
    print("This toolkit is intended for use in isolated lab environments only.")
    print("All testing must be performed on equipment and networks you own")
    print("or have explicit permission to test.")
    print_blank()
    print("Captured traffic and detections should be handled separately using WSTT.")
    print_blank()
    print("Author : Paul Smurthwaite")
    print("Module : TM470-25B")
    print("Date   : Mar 2025")

    print_blank()
    print_prompt("Press Enter to return to menu")
    input()
