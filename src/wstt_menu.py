#!/usr/bin/env python3
import pyfiglet
import os
import subprocess

def clear_screen():
    """Clears the terminal screen for better readability."""
    os.system("cls" if os.name == "nt" else "clear")

def show_menu():
    """Displays the main WSTT menu with dynamic ASCII text."""
    clear_screen()
    
    # Generate dynamic ASCII banner
    ascii_banner = pyfiglet.figlet_format("WSTT", font="ansi_shadow")
    print("\033[94m" + ascii_banner + "\033[0m")  # Red color for banner
    
    # Should include author's name and the purpose of the tool, module, (C) licence, etc.
    print("\n[ WSTT - Wireless Security Testing Toolkit ]\n")
    print("[1] Full Wi-Fi Scan")
    print("[2] Targeted Wi-Fi Scan")
    print("[3] View Scan Results")
    print("[4] Exit")

def run_full_scan():
    """Runs a full Wi-Fi scan using wstt_full-scan.py."""

    # we want the user to be able to see what interfaces are available
    # and select one - saves on input errors
    interface = input("\nEnter your wireless interface (e.g., wlan0): ")
    subprocess.run(["python3", "wstt_full-scan.py", "-i", interface])

def run_target_scan():
    """Runs a targeted Wi-Fi scan using wstt_target-scan.py."""
    interface = input("\nEnter your wireless interface (e.g., wlan0): ")
    subprocess.run(["python3", "wstt_target-scan.py", "-i", interface])

def view_scan_results():
    """Lists scan results from the scans/ directory."""

    # this should call a script that performs this function
    scans_dir = os.path.join(os.path.dirname(__file__), "scans")
    if not os.path.exists(scans_dir):
        print("[!] No scans found. Run a scan first.")
        return

    scan_files = os.listdir(scans_dir)
    if not scan_files:
        print("[!] No scan results found.")
        return

    print("\nAvailable Scan Results:")
    for idx, file in enumerate(scan_files, start=1):
        print(f"[{idx}] {file}")

def main():
    """Main function to handle user input."""

    # Is this the most efficient way to capture user input?
    while True:
        show_menu()
        choice = input("\n[+] Select an option: ")
        
        if choice == "1":
            run_full_scan()
        elif choice == "2":
            run_target_scan()
        elif choice == "3":
            view_scan_results()
        elif choice == "4":
            print("\nExiting WSTT Menu.")
            break
        else:
            print("\n[!] Invalid option. Please try again.")

if __name__ == "__main__":
    main()
