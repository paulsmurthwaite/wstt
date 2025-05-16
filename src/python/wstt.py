#!/usr/bin/env python3
"""wstt.py

Main entry point for the Wireless Security Testing Toolkit (WSTT) menu interface.

This script provides a simple, operator-friendly CLI for accessing key toolkit functions such as scanning, capturing, and detection.  It is designed to offer a clear and low-complexity user experience, suitable for field use in SME environments.

The menu system acts as the central launcher for Bash and Python-based components of the toolkit, with screen clearing and section redrawing used to improve usability without introducing graphical complexity.

Author:      Paul Smurthwaite
Date:        2025-05-14
Module:      TM470-25B
"""


import pyfiglet
import os
import subprocess

def get_interface_details():
    """
    Returns (interface, state, mode) from get-current-interface.sh.
    """
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "bash", "get-current-interface.sh")
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

def pause_on_invalid():
    """Display invalid input message and pause."""
    print("\n[!] Invalid option. Please try again.")
    input("[Press Enter to continue]")

def clear_screen():
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")

def print_header(title="Wireless Security Testing Toolkit"):
    """Print section header."""
    print(f"\033[94m[ {title} ]\033[0m")

def print_interface_status():
    """Print the current interface, state, and mode."""
    interface, state, mode = get_interface_details()
    print(f"Interface: {interface}")
    print(f"State:     {state}")
    print(f"Mode:      {mode}")
    print()

def show_menu():
    """Display main menu."""
    clear_screen()
    
    # Generate ASCII banner
    ascii_banner = pyfiglet.figlet_format("WSTT", font="ansi_shadow")
    print("\033[94m" + ascii_banner + "\033[0m")
    print_header()
    print()

    # Display interface details
    print_interface_status()

    # Generate menu
    print("[1] Change Interface State")
    print("[2] Change Interface Mode")
    print("[3] Reset Interface")
    print("[4] Scan Wireless Traffic")
    print("[5] Capture Wireless Packets")
    print("[6] Wireless Threat Detection")

    print("\n[0] Exit")

def run_bash_script(script_name, pause=True, capture=True, title=None):
    """
    Executes a Bash script located under /src/bash.
    
    Args:
        script_name (str): Script name without extension.
        title (str): Optional header to display before execution
        pause (bool): Whether to wait for user input after execution.
    """
    clear_screen()

    if title:
        print_header(title)
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
        print(f"[!] Script failed: {script_name}.sh")
        if e.stderr:
            print(e.stderr.strip())

    if pause:
        input("\n[Press Enter to return to menu]")

def run_python_script(script_name, pause=True, title=None):
    """
    Executes a Python script located under /src/python/detect/.

    Args:
        script_name (str): Name of the script without '.py'
        title (str): Optional header to display before execution
    """
    clear_screen()
    if title:
        print_header(title)
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
            print(f"[!] Script failed during execution: {script_name}.py")

    if pause:
        input("\n[Press Enter to return to menu]")

def interface_state():
    """Interface State submenu."""

    def set_interface_down():
        run_bash_script("set-interface-down", pause=False, capture=False, title="Change Interface State")

    def set_interface_up():
        run_bash_script("set-interface-up", pause=False, capture=False, title="Change Interface State")

    actions = {
        "1": set_interface_down,
        "2": set_interface_up
    }

    while True:
        clear_screen()
        print_header()
        print()
        print_header("Change Interface State")
        print()
        print_interface_status()
        print("[1] Set current interface DOWN")
        print("[2] Bring current interface UP")

        print("\n[0] Return to Main Menu")

        choice = input("\n[+] Select an option: ")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            clear_screen()
            action()
        else:
            pause_on_invalid()

def interface_mode():
    """Interface mode submenu."""

    def switch_to_managed():
        run_bash_script("set-mode-managed", pause=False, capture=False, title="Change Interface Mode")

    def switch_to_monitor():
        run_bash_script("set-mode-monitor", pause=False, capture=False, title="Change Interface Mode")

    actions = {
        "1": switch_to_managed,
        "2": switch_to_monitor
    }

    while True:
        clear_screen()
        print_header()
        print()
        print_header("Change Interface Mode")
        print()
        print_interface_status()
        print("[1] Switch to Managed mode")
        print("[2] Switch to Monitor mode")

        print("\n[0] Return to Main Menu")

        choice = input("\n[+] Select an option: ")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            clear_screen()
            action()
        else:
            pause_on_invalid()

def interface_reset():
    """Reset interface submenu."""

    def perform_soft_reset():
        run_bash_script("reset-interface-soft", pause=False, capture=False, title="Reset Interface (Soft)")

    def perform_hard_reset():
        run_bash_script("reset-interface-hard", pause=False, capture=False, title="Reset Interface (Hard)")

    actions = {
        "1": perform_soft_reset,
        "2": perform_hard_reset
    }

    while True:
        clear_screen()
        print_header()
        print()
        print_header("Reset Interface")
        print()
        print_interface_status()
        print("[1] Perform Soft Reset (Interface Down/Up)")
        print("[2] Perform Hard Reset (Interface Unload/Reload)")

        print("\n[0] Return to Main Menu")

        choice = input("\n[+] Select an option: ")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            clear_screen()
            action()
        else:
            pause_on_invalid()

def run_scan():
    """Scan traffic handler."""
    run_bash_script("wstt_scan", pause=True, capture=False, title="Scan Wireless Traffic to file")

def run_capture():
    """Capture packets handler."""
    run_bash_script("wstt_capture", pause=True, capture=False, title="Capture Wireless Packets to file")

def run_threat_detection():
    """Wireless threat detection submenu."""

    def detect_t001():
        run_python_script("detect_t001", pause=True, title="T001 – Unencrypted Traffic Capture")

    def detect_t002():
        run_python_script("detect_t002", pause=True, title="T002 – Probe Request Snooping")

    def detect_t003():
        run_python_script("detect_t003", pause=True, title="T003 – SSID Harvesting")

    def detect_t004():
        run_python_script("detect_t004", pause=True, title="T004 – Evil Twin Attack")

    def detect_t005():
        run_python_script("detect_t005", pause=True, title="T005 – Open Rogue AP")

    def detect_t006():
        run_python_script("detect_t006", pause=True, title="T006 – Misconfigured Access Point")

    def detect_t007():
        run_python_script("detect_t007", pause=True, title="T007 – Deauthentication Flood")

    def detect_t008():
        run_python_script("detect_t008", pause=True, title="T008 – Beacon Flood")

    def detect_t009():
        run_python_script("detect_t009", pause=True, title="T009 – Authentication Flood")

    def detect_t014():
        run_python_script("detect_t014", pause=True, title="T014 – ARP Spoofing from Wireless Entry Point")

    def detect_t015():
        run_python_script("detect_t015", pause=True, title="T015 – Malicious Hotspot Auto-Connect")

    def detect_t016():
        run_python_script("detect_t016", pause=True, title="T016 – Directed Probe Response")

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
        clear_screen()
        print_header("Wireless Threat Detection")
        print()

        print_header("Access Point Threats")
        print("[1]  T001 – Unencrypted Traffic Capture")
        print("[2]  T002 – Probe Request Snooping")
        print("[3]  T003 – SSID Harvesting")
        print("[4]  T004 – Evil Twin Attack")
        print("[5]  T005 – Open Rogue AP")
        print("[6]  T006 – Misconfigured Access Point")
        print("[7]  T008 – Beacon Flood")
        print()

        print_header("Client Exploits")
        print("[8]  T007 – Deauthentication Flood")
        print("[9]  T009 – Authentication Flood")
        print("[10] T014 – ARP Spoofing from Wireless Entry Point")
        print("[11] T015 – Malicious Hotspot Auto-Connect")
        print("[12] T016 – Directed Probe Response")

        print("\n[0] Return to Main Menu")

        choice = input("\n[+] Select a threat scenario to run: ")

        if choice == "0":
            break

        action = actions.get(choice)
        if action:
            clear_screen()
            action()
        else:
            pause_on_invalid()

def main():
    """User input handler."""

    while True:
        show_menu()
        choice = input("\n[+] Select an option: ")
        
        if choice == "1":
            interface_state()
        elif choice == "2":
            interface_mode()
        elif choice == "3":
            interface_reset()
        elif choice == "4":
            run_scan()
        elif choice == "5":
            run_capture()
        elif choice == "6":
            run_threat_detection()
        elif choice == "0":
            print("\nExiting to shell.")
            break
        else:
            pause_on_invalid()

if __name__ == "__main__":
    main()
