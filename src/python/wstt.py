#!/usr/bin/env python3
"""wstt.py

Main entry point for the Wireless Security Testing Toolkit (WSTT) menu interface.

This script provides a simple, operator-friendly CLI for accessing key toolkit functions such as scanning, capturing, and detection.  It is designed to offer a clear and low-complexity user experience, suitable for field use in SME environments.

The menu system acts as the central launcher for Bash and Python-based components of the toolkit, with screen clearing and section redrawing used to improve usability without introducing graphical complexity.

Author:      Paul Smurthwaite
Date:        2025-05-14
Module:      TM470-25B
"""

import os
import pyfiglet
import subprocess
from helpers.theme import colour

# ─── UI Helpers ───
# UI Banner
def ui_banner():
    """
    Display ASCII banner.
    """
    ascii_banner = pyfiglet.figlet_format("WSTT", font="ansi_shadow")
    print(colour(ascii_banner, "header"))

# UI Header
def ui_header(title="Wireless Security Testing Toolkit"):
    """
    Display section header.
    """
    styled = colour(colour(f"[ {title} ]", "bold"), "header")
    print(styled)

# UI Divider
def ui_divider():
    """
    Display divider.
    """
    print(colour("-----------------------------------", "neutral"))
    print()

# UI Subtitle
def ui_subtitle():
    """
    Display combined subtitle.
    """
    ui_divider()
    print_interface_status()
    ui_divider()

# UI Standard Header
def ui_standard_header(menu_title=None):
    """
    Render standard UI header block: banner, main title, subtitle.
    Optionally takes a menu title to display immediately after.
    """
    ui_banner()       # ASCII banner
    ui_header()       # Toolkit title
    print()
    ui_subtitle()     # Divider + interface + service info

    if menu_title:
        ui_header(menu_title)  # Current menu title
        print()

# UI Clear Screen
def ui_clear_screen():
    """
    Clear terminal screen.
    """
    os.system("cls" if os.name == "nt" else "clear")

# UI Invalid Option
def ui_pause_on_invalid():
    """
    Display invalid input message and pause.
    """
    print(colour("\n[!] Invalid option. Please try again.", "warning"))
    input("[Press Enter to continue]")

# ─── Display Interface ───
# 
def print_interface_status():
    """
    Print the current interface, state, and mode.
    """
    interface, state_raw, mode_raw = get_interface_details()

    state = state_raw.title()
    mode = "AP" if mode_raw.lower() == "ap" else mode_raw.title()

    # Determine colours
    interface_display = colour(interface, "info")
    state_display = colour(state, "success" if state.lower() == "up" else "warning")

    if mode_raw.lower() == "managed":
        mode_display = colour(mode, "success")
    elif mode_raw.lower() == "monitor":
        mode_display = colour(mode, "warning")
    elif mode_raw.lower() == "ap":
        mode_display = colour(mode, "warning")
    else:
        mode_display = colour(mode, "reset")

    # Output
    print(f"[ Interface       ] {interface_display}")
    print(f"[ Interface State ] {state_display}")
    print(f"[ Interface Mode  ] {mode_display}")
    print()

# ─── Interface Helpers ───
#
def get_interface_details():
    """
    Returns (interface, state, mode) from get-current-interface.sh.
    """
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "bash", "services", "get-current-interface.sh")
    )

    if not os.path.exists(script_path):
        return ("[!] Not found", "[!] Not found", "[!] Not found")

    try:
        result = subprocess.run(["bash", script_path], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().splitlines()
        interface = lines[0].split(":")[1].strip().upper() if len(lines) > 0 else "?"
        state     = lines[1].split(":")[1].strip().upper() if len(lines) > 1 else "?"
        mode      = lines[2].split(":")[1].strip().upper() if len(lines) > 2 else "?"
        return (interface, state, mode)
    except subprocess.CalledProcessError:
        return ("[!] Script error", "[!] Script error", "[!] Script error")

def get_current_interface():
    return get_interface_details()[0]

def get_interface_state():
    return f"State:     {get_interface_details()[1]}"

def get_interface_mode():
    return f"Mode:      {get_interface_details()[2]}"

# ─── Display Main Menu ───
# 
def show_menu():
    """
    Display main menu.
    """
    ui_clear_screen()

    # Header block
    ui_standard_header("Main Menu")

    # Menu block
    ui_header("Acquisition")
    print("[1] Scan Wireless Traffic")
    print("[2] Capture Wireless Frames")
    print()
    ui_header("Analysis")
    print("[3] Threat Detection")
    print()
    ui_header("Services")
    print("[4] Service Control")
    print()
    print("[5] Help | About")

    # Exit option
    print("\n[0] Exit")

# ─── Bash Script Handler ───
#
def run_bash_script(script_name, pause=True, capture=True, clear=True, title=None):
    """
    Executes a Bash script located under /src/bash.
    
    Args:
        script_name (str): Script name without extension.
        title (str): Optional header to display before execution
        pause (bool): Whether to wait for user input after execution.
    """
    if clear:
        ui_clear_screen()

    if title:
        ui_header(title)
        print()

    # Bash script path
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "bash", f"{script_name}.sh")
    )

    if not os.path.exists(script_path):
        print(f"[!] Script not found: {script_name}.sh")
        return
    
    try:
        if capture:
            result = subprocess.run(
                ["bash", script_path],
                check=True,
                capture_output=True,
                text=True
            )
        else:
            subprocess.run(["bash", script_path], check=True)
    
    except subprocess.CalledProcessError as e:
        print(colour(f"[!] Script failed: {script_name}.sh", "warning"))
        if e.stderr:
            print(e.stderr.strip())

    if pause:
        input("\n[Press Enter to return to menu]")

# ─── Python Script Handler ───
#
def run_python_script(script_name, pause=True, capture=True, clear=True, title=None):
    """
    Executes a Python script located under /src/python/detect/.

    Args:
        script_name (str): Name of the script without '.py'
        title (str): Optional header to display before execution
    """
    if clear:
        ui_clear_screen()

    if title:
        ui_header(title)
        print()

    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "detect", f"{script_name}.py")
    )

    if not os.path.exists(script_path):
        print(f"[!] Script not found: {script_name}.py")
    else:
        try:
            subprocess.run(["python3", script_path], check=True)
        except subprocess.CalledProcessError:
            print(f"[x] Script failed during execution: {script_name}.py")

    if pause:
        input("\n[Press Enter to return to menu]")

def run_scan():
    """
    Scan traffic handler.
    """
    print()
    run_bash_script("utilities/wstt_scan", pause=True, capture=False, clear=False, title="Scan Wireless Traffic to file")

def run_capture():
    """
    Capture packets handler.
    """
    print()
    run_bash_script("utilities/wstt_capture", pause=True, capture=False, clear=False, title="Capture Wireless Packets to file")

def run_threat_detection():
    """
    Wireless threat detection submenu.
    """
    def detect_t001():
        run_python_script("t001", pause=True, clear=False, title="T001 – Unencrypted Traffic Capture")

    def detect_t002():
        run_python_script("t002", pause=True, clear=False, title="T002 – Probe Request Snooping")

    def detect_t003():
        run_python_script("t003", pause=True, clear=False, title="T003 – SSID Harvesting")

    def detect_t004():
        run_python_script("t004", pause=True, clear=False, title="T004 – Evil Twin Attack")

    def detect_t005():
        run_python_script("t005", pause=True, clear=False, title="T005 – Open Rogue AP")

    def detect_t006():
        run_python_script("t006", pause=True, clear=False, title="T006 – Misconfigured Access Point")

    def detect_t007():
        run_python_script("t007", pause=True, clear=False, title="T007 – Deauthentication Flood")

    def detect_t008():
        run_python_script("t008", pause=True, clear=False, title="T008 – Beacon Flood")

    def detect_t009():
        run_python_script("t009", pause=True, clear=False, title="T009 – Authentication Flood")

    def detect_t014():
        run_python_script("t014", pause=True, clear=False, title="T014 – ARP Spoofing from Wireless Entry Point")

    def detect_t015():
        run_python_script("t015", pause=True, clear=False, title="T015 – Malicious Hotspot Auto-Connect")

    def detect_t016():
        run_python_script("t016", pause=True, clear=False, title="T016 – Directed Probe Response")

    actions = {
        "1":  detect_t001,
        "2":  detect_t002,
        "3":  detect_t003,
        "4":  detect_t004,
        "5":  detect_t005,
        "6":  detect_t006,
        "7":  detect_t007,
        "8":  detect_t008,
        "9":  detect_t009,
        "10": detect_t014,
        "11": detect_t015,
        "12": detect_t016
    }

    while True:
        ui_clear_screen()

        # Header block
        ui_standard_header("Threat Detection Scenarios")

        print("[1]  T001 – Unencrypted Traffic Capture")
        print("[2]  T002 – Probe Request Snooping")
        print("[3]  T003 – SSID Harvesting")
        print("[4]  T004 – Evil Twin Attack")
        print("[5]  T005 – Open Rogue AP")
        print("[6]  T006 – Misconfigured Access Point")
        print("[7]  T007 – Deauthentication Flood")
        print("[8]  T008 – Beacon Flood")
        print("[9]  T009 – Authentication Flood")
        print("[10] T014 – ARP Spoofing from Wireless Entry Point")
        print("[11] T015 – Malicious Hotspot Auto-Connect")
        print("[12] T016 – Directed Probe Response")

        print("\n[0] Return to Main Menu")

        choice = input("\n[+] Select a scenario to run: ")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            print()
            action()
        else:
            ui_pause_on_invalid()

def service_control():
    """
    Service Control submenu.
    """

    def interface_state():
        """
        Interface State submenu.
        """

        def set_interface_down():
            run_bash_script("services/set-interface-down", pause=False, capture=False, clear=False, title="Change Interface State")

        def set_interface_up():
            run_bash_script("services/set-interface-up", pause=False, capture=False, clear=False, title="Change Interface State")

        actions = {
            "1": set_interface_down,
            "2": set_interface_up
        }

        while True:
            ui_clear_screen()
            
            # Header block
            ui_standard_header("Set Interface State")
                    
            # Menu block                    
            print("[1] Set interface state DOWN")
            print("[2] Set interface state UP")
            print("\n[0] Return to Service Control Menu")

            # Input
            choice = input("\n[?] Select an option: ")

            if choice == "0":
                break

            action = actions.get(choice)
            if action:
                print()
                action()
            else:
                ui_pause_on_invalid()

    def interface_mode():
        """
        Interface mode submenu.
        """

        def switch_to_managed():
            run_bash_script("services/set-mode-managed", pause=False, capture=False, clear=False, title="Change Interface Mode")

        def switch_to_monitor():
            run_bash_script("services/set-mode-monitor", pause=False, capture=False, clear=False, title="Change Interface Mode")

        actions = {
            "1": switch_to_managed,
            "2": switch_to_monitor
        }

        while True:
            ui_clear_screen()

            # Header block
            ui_standard_header("Set Interface Mode")

            # Menu block
            print("[1] Set interface mode MANAGED")
            print("[2] Set interface mode MONITOR")
            print("\n[0] Return to Service Control Menu")

            # Input
            choice = input("\n[?] Select an option: ")

            if choice == "0":
                break

            action = actions.get(choice)
            if action:
                print()
                action()
            else:
                ui_pause_on_invalid()

    def interface_reset():
        """
        Reset interface submenu.
        """

        def perform_soft_reset():
            run_bash_script("services/reset-interface-soft", pause=False, capture=False, clear=False, title="Reset Interface (Soft)")

        def perform_hard_reset():
            run_bash_script("services/reset-interface-hard", pause=False, capture=False, clear=False, title="Reset Interface (Hard)")

        actions = {
            "1": perform_soft_reset,
            "2": perform_hard_reset
        }

        while True:
            ui_clear_screen()

            # Header block
            ui_standard_header("Reset Interface")

            print("[1] Perform Soft Reset (Interface Down/Up)")
            print("[2] Perform Hard Reset (Interface Unload/Reload)")
            print("\n[0] Return to Service Control Menu")

            # Input
            choice = input("\n[?] Select an option: ")

            if choice == "0":
                break

            action = actions.get(choice)
            if action:
                print()
                action()
            else:
                ui_pause_on_invalid()

    actions = {
        "1": interface_state,
        "2": interface_mode,
        "3": interface_reset
    }

    while True:
        ui_clear_screen()

        # Header block
        ui_standard_header("Service Control")

        print("[1] Change Interface State")
        print("[2] Change Interface Mode")
        print("[3] Reset Interface")
        print("\n[0] Return to Main Menu")

        # Input
        choice = input("\n[?] Select an option: ")

        if choice == "0":
            break

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
    ui_clear_screen()

    # Header block
    ui_standard_header("Help | About")

    print("WSTT (Wireless Security Testing Toolkit) provides a menu-driven interface")
    print("to launch predefined wireless attack scenarios in a controlled")
    print("testing environment.  Each attack corresponds to a specific threat")
    print("profile and is executed using underlying Bash-based tools.")
    print()
    print("This toolkit is intended for use in isolated lab environments only.")
    print("All testing must be performed on equipment and networks you own")
    print("or have explicit permission to test.")
    print()
    print("Captured traffic and detections should be handled separately using WSTT.")
    print()
    print("Author : Paul Smurthwaite")
    print("Module : TM470-25B")
    print("Date   : Mar 2025")

    # Input
    input("\n[Press Enter to return to menu]")

def main():
    """User input handler."""

    while True:
        show_menu()
        choice = input("\n[?] Select an option: ")
        
        if choice == "1":
            run_scan()
        elif choice == "2":
            run_capture()
        elif choice == "3":
            run_threat_detection()
        elif choice == "4":
            service_control()
        elif choice == "5":
            help_about()
        elif choice == "0":
            print(colour("\n[+] Exiting to shell.", "success"))
            break
        else:
            ui_pause_on_invalid()

if __name__ == "__main__":
    main()
