#!/usr/bin/env python3
"""wstt.py

Main entry point for the Wireless Security Testing Toolkit (WSTT) menu interface.

This script provides a simple, operator-friendly CLI for accessing key toolkit functions such as scanning, capturing, and detection.  It is designed to offer a clear and low-complexity user experience, suitable for field use in SME environments.

The menu system acts as the central launcher for Bash and Python-based components of the toolkit, with screen clearing and section redrawing used to improve usability without introducing graphical complexity.

Author:      Paul Smurthwaite
Date:        2025-05-14
Module:      TM470-25B
"""

# ─── External Modules  ───
import logging
import sys

# ─── Local Modules ───
from helpers.logger import setup_logger
from helpers.output import print_blank, print_prompt, print_success
from helpers.preflight import run_preflight_checks
from helpers.system import (
    run_bash_script,
    run_python_script,
)
from helpers.ui import (
    display_main_menu,
    display_scan_menu,
    display_capture_menu,
    display_threat_detection_menu,
    display_service_control_menu,
    display_interface_state_menu,
    display_interface_mode_menu,
    display_interface_reset_menu,
    display_help_about_screen,
    ui_pause_on_invalid
)

log = logging.getLogger(__name__)

def run_scan():
    """
    Scan traffic handler.
    """
    log.info("Entering Scan submenu.")

    actions = {
        "1": lambda: run_bash_script("utilities/wstt_scan", args=["--full"], pause=True, capture=False, clear=True, title="Full Scan"),
        "2": lambda: run_bash_script("utilities/wstt_scan", args=["--channel"], pause=True, capture=False, clear=True, title="Filtered Scan (Channel)"),
        "3": lambda: run_bash_script("utilities/wstt_scan", args=["--bssid"], pause=True, capture=False, clear=True, title="Filtered Scan (BSSID & Channel)"),
    }

    while True:
        display_scan_menu()

        print_blank()
        print_prompt("Select a scan type: ")
        choice = input()

        if choice == "0":
            break
        log.info("User selected scan type: %s", choice)

        action = actions.get(choice)
        if action:
            action()
        else:
            ui_pause_on_invalid()

def run_capture():
    """
    Capture packets handler.
    """
    log.info("Entering Capture submenu.")

    actions = {
        "1": lambda: run_bash_script("utilities/wstt_capture", args=["--full"], pause=True, capture=False, clear=True, title="Full Capture"),
        "2": lambda: run_bash_script("utilities/wstt_capture", args=["--channel"], pause=True, capture=False, clear=True, title="Filtered Capture (Channel)"),
        "3": lambda: run_bash_script("utilities/wstt_capture", args=["--bssid"], pause=True, capture=False, clear=True, title="Filtered Capture (BSSID & Channel)"),
    }

    while True:
        display_capture_menu()

        print_blank()
        print_prompt("Select a capture type: ")
        choice = input()

        if choice == "0":
            break
        log.info("User selected capture type: %s", choice)

        action = actions.get(choice)
        if action:
            action()
        else:
            ui_pause_on_invalid()

def run_threat_detection():
    """
    Wireless threat detection submenu.
    """
    log.info("Entering Threat Detection submenu.")

    # Define scenarios as data to avoid repetitive function definitions
    scenarios = [
        ("t001", "T001 – Unencrypted Traffic Capture"),
        ("t002", "T002 – Probe Request Snooping"),
        ("t003", "T003 – SSID Harvesting"),
        ("t004", "T004 – Evil Twin Attack"),
        ("t005", "T005 – Open Rogue AP"),
        ("t006", "T006 – Misconfigured Access Point"),
        ("t007", "T007 – Deauthentication Flood"),
        ("t008", "T008 – Beacon Flood"),
        ("t009", "T009 – Authentication Flood"),
        ("t014", "T014 – ARP Spoofing from Wireless Entry Point"),
        ("t015", "T015 – Malicious Hotspot Auto-Connect"),
        ("t016", "T016 – Directed Probe Response"),
    ]

    # Build the actions dictionary dynamically
    actions = {}
    for i, (script_name, title) in enumerate(scenarios, 1):
        # Use a default argument in lambda to capture the correct values from the loop
        actions[str(i)] = lambda s=script_name, t=title: run_python_script(s, pause=True, clear=False, title=t)

    while True:
        display_threat_detection_menu()

        print_blank()
        print_prompt("Select a scenario to run: ")
        choice = input()

        if choice == "0":
            break
        log.info("User selected detection scenario: %s", choice)

        action = actions.get(choice)
        if action:
            print_blank()
            action()
        else:
            ui_pause_on_invalid()

def service_control():
    """
    Service Control submenu.
    """
    log.info("Entering Service Control submenu.")

    def interface_state():
        """
        Interface State submenu.
        """

        actions = {
            "1": lambda: run_bash_script("services/set-interface-down", pause=False, capture=False, clear=False, title="Change Interface State"),
            "2": lambda: run_bash_script("services/set-interface-up", pause=False, capture=False, clear=False, title="Change Interface State")
        }

        while True:
            display_interface_state_menu()

            # Input
            print_blank()
            print_prompt("Select an option: ")
            choice = input()

            if choice == "0":
                break
            log.info("User selected interface state option: %s", choice)

            action = actions.get(choice)
            if action:
                print_blank()
                action()
            else:
                ui_pause_on_invalid()

    def interface_mode():
        """
        Interface mode submenu.
        """

        actions = {
            "1": lambda: run_bash_script("services/set-mode-managed", pause=False, capture=False, clear=False, title="Change Interface Mode"),
            "2": lambda: run_bash_script("services/set-mode-monitor", pause=False, capture=False, clear=False, title="Change Interface Mode")
        }

        while True:
            display_interface_mode_menu()

            # Input
            print_blank()
            print_prompt("Select an option: ")
            choice = input()

            if choice == "0":
                break
            log.info("User selected interface mode option: %s", choice)

            action = actions.get(choice)
            if action:
                print_blank()
                action()
            else:
                ui_pause_on_invalid()

    def interface_reset():
        """
        Reset interface submenu.
        """

        actions = {
            "1": lambda: run_bash_script("services/reset-interface-soft", pause=False, capture=False, clear=False, title="Reset Interface (Soft)"),
            "2": lambda: run_bash_script("services/reset-interface-hard", pause=False, capture=False, clear=False, title="Reset Interface (Hard)")
        }

        while True:
            display_interface_reset_menu()

            # Input
            print_blank()
            print_prompt("Select an option: ")
            choice = input()

            if choice == "0":
                break
            log.info("User selected interface reset option: %s", choice)

            action = actions.get(choice)
            if action:
                print_blank()
                action()
            else:
                ui_pause_on_invalid()

    actions = {
        "1": interface_state,
        "2": interface_mode,
        "3": interface_reset
    }

    while True:
        display_service_control_menu()

        # Input
        print_blank()
        print_prompt("Select an option: ")
        choice = input()

        if choice == "0":
            break
        log.info("User selected service control option: %s", choice)

        action = actions.get(choice)
        if action:
            ui_clear_screen()
            action()
        else:
            ui_pause_on_invalid()

def help_about():
    """
    Help | About submenu.
    """
    log.info("User selected 'Help | About'.")
    display_help_about_screen()
    
def main():
    """User input handler."""

    # Run pre-flight checks before initializing the UI or logger.
    # If checks fail, the function will print errors and return False.
    if not run_preflight_checks():
        sys.exit(1)

    setup_logger("main_session")
    log.info("WSTT main menu initialised.")

    actions = {
        "1": run_scan,
        "2": run_capture,
        "3": run_threat_detection,
        "4": service_control,
        "5": help_about,
    }

    while True:
        display_main_menu()
        print_blank()
        print_prompt("Select an option: ")
        choice = input()

        if choice == "0":
            print_blank()
            print_success("Exiting to shell.")
            log.info("User selected 'Exit'. Shutting down.")
            break

        action = actions.get(choice)
        if action:
            action()
        else:
            ui_pause_on_invalid()

if __name__ == "__main__":
    main()