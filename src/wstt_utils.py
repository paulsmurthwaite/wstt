#!/usr/bin/env python3
"""wstt_utils.py

Information goes here

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      [Module Code]
"""


import click
import json
import os
import subprocess
import time
from tabulate import tabulate
from wstt_logging import log_message

config_file = "wstt_config.json"

# Load Configuration
def load_config():
    """Load configuration from JSON file, creating it if missing."""
    if not os.path.exists(config_file):
        # Create default config if file doesn't exist
        default_config = {
            "interface": None,
            "log_file": "/logs/wstt.log"  # Default log file location
        }
        with open(config_file, "w") as f:
            json.dump({}, f, indent=4)

    try:
        with open(config_file, "r") as f:
            return json.load(f)  # Load the existing config
    except json.JSONDecodeError:
        # If the file is corrupted, reset it
        default_config = {
            "interface": None,
            "log_file": "/logs/wstt.log"
        }
        with open(config_file, "w") as f:
            json.dump({}, f, indent=4)
        return {}

# Save Configuration
def save_config(config):
    """Save the configuration to JSON file."""
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

# Get Selected Interface
def get_selected_interface():
    """Retrieve the selected interface from the config file."""
    config = load_config()
    return config.get("interface", None)

# List Interfaces
@click.command()
def get_interfaces():
    """List available wireless interfaces."""

    click.echo("\n\033[94m[ Available Interfaces ]\033[0m")  # Blue heading

    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            click.echo(result.stdout)
        else:
            log_message("WARNING", "No wireless interfaces found.")
            click.echo("[ERROR] No wireless interfaces found.", err=True)
    except subprocess.CalledProcessError:
        log_message("ERROR", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?")
        click.echo("[ERROR] Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?", err=True)

# Set Interface
@click.command()
@click.pass_context
def set_interface(ctx):
    """Select from a list of available interfaces."""
    click.echo("\n\033[94m[ Select Interface ]\033[0m")  # Blue heading

    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if not result.stdout.strip():
            log_message("WARNING", "No wireless interfaces found when attempting to set an interface.")
            click.echo("\033[91m[ERROR] No wireless interfaces found.\033[0m", err=True)
            return

        click.echo(result.stdout)  # Display full output to the user
        selected_interface = click.prompt("\nEnter the interface name to use (e.g., wlx00c0cab4b58c)", type=str)

        # Load existing config if available
        config = {}
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                config = json.load(f)

        # Update and write the new interface selection
        config["interface"] = selected_interface
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)

        log_message("INFO", f"User selected interface: {selected_interface}")       
        click.echo(f"\n\033[92m[+] Selected interface: {selected_interface}\033[0m")

    except subprocess.CalledProcessError:
        log_message("ERROR", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?")
        click.echo("\033[91m[ERROR] Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?\033[0m", err=True)

# Show Interface
@click.command()
def show_interface():
    """Show the currently selected wireless interface details."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to display interface details.")
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo("\n\033[94m[ Current Interface ]\033[0m\n")  # Blue heading

    try:
        # Get MAC Address & Interface State
        mac_address, state = "Unknown", "Unknown"
        ip_result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True, check=True)
        for line in ip_result.stdout.split("\n"):
            if "link/ether" in line:
                mac_address = line.split()[1]  # Extract MAC Address
            if "state" in line:
                state = line.split("state")[1].split()[0].capitalize()  # Extract UP/DOWN state

        # Get Interface Mode
        mode = get_mode(interface)

        # Get Interface Driver
        driver = "Unknown"
        lshw_result = subprocess.run(["sudo", "lshw", "-C", "network"], capture_output=True, text=True, check=True)
        in_block = False

        for line in lshw_result.stdout.split("\n"):
            if "logical name:" in line and interface in line:
                in_block = True  # Start reading the correct interface block
            elif "logical name:" in line and interface not in line:
                in_block = False  # Reset if another interface starts

            if in_block and "driver=" in line:
                driver = line.split("driver=")[-1].split()[0]  # Extract correct driver
                break

        # Get Chipset
        chipset, capabilities = "Unknown", "Unknown"
        airmon_result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        for line in airmon_result.stdout.split("\n"):
            columns = line.split()
            if len(columns) >= 4 and columns[1] == interface:
                chipset = " ".join(columns[3:])  # Extract Chipset from last column
                capabilities = columns[3]  # Extract Capabilities (802.11a/b/g/n/ac)

        # Format Ouput
        table_data = [[interface, mac_address, state, mode, driver, chipset]]
        headers = ["Interface", "MAC Address", "State", "Mode", "Driver", "Chipset"]
        table = tabulate(table_data, headers=headers, tablefmt="plain")

        click.echo(table)
        click.echo()  # Ensure a blank line before returning to command prompt

    except subprocess.CalledProcessError:
        log_message("ERROR", "Failed to retrieve interface details.  Are 'ip', 'iw', 'airmon-ng', and 'lshw' installed?")
        click.echo("\033[91m[ERROR] Failed to retrieve interface details.  Are 'ip', 'iw', 'airmon-ng', and 'lshw' installed?\033[0m", err=True)

# Set Interface State
def set_interface_state(state):
    """Bring the selected wireless interface UP or DOWN."""
    interface = get_selected_interface()
    if not interface:
        log_message("WARNING", "No interface selected when attempting to bring interface UP/DOWN.")
        click.echo("\033[91m[ERROR] No interface selected.\033[0m")
        return

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, state], check=True)
        log_message("INFO", f"Interface {interface} set to {state}.")
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to bring interface {interface} {state}.")
        click.echo(f"\033[91m[ERROR] Failed to bring the interface {state}.\033[0m", err=True)

# Get Interface Mode
def get_mode(interface):
    """Retrieve the current mode (Managed/Monitor) of the wireless interface."""
    mode = "Unknown"
    try:
        iw_result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Extract mode
                break
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to retrieve mode for interface {interface}.")
    return mode

# Mode Command
@click.command("mode")
@click.argument("mode_type", type=click.Choice(["managed", "monitor"], case_sensitive=False))
def set_mode(mode_type):
    """Set the interface mode (managed or monitor)."""
    if mode_type == "managed":
        set_managed_mode()
    elif mode_type == "monitor":
        set_monitor_mode()

# Set Mode
def set_mode_type(mode_type):
    """Set the interface mode to Managed or Monitor."""
    interface = get_selected_interface()
    if not interface:
        log_message("WARNING", "No interface selected when attempting to change mode.")
        click.echo("\033[91m[ERROR] No interface selected.\033[0m")
        return

    try:
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", mode_type], check=True)
        log_message("INFO", f"Interface {interface} mode changed to {mode_type}.")
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to {mode_type} Mode.")
        click.echo(f"\033[91m[ERROR] Failed to switch interface to {mode_type} Mode.\033[0m")

# Managed Mode
def set_managed_mode():
    """Set the selected wireless interface to Managed Mode."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to switch to Managed Mode.")
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo("\n\033[94m[ Set Managed Mode ]\033[0m\n")

    try:
        # Get Mode
        if get_mode(interface) == "Managed":
            log_message("INFO", f"Interface {interface} is already in Managed Mode. No changes made.")
            click.echo(f"\033[93m[INFO] Interface {interface} is already in Managed Mode. No changes made.\033[0m\n")
            return

        set_interface_state("down")
        set_mode_type("managed")
        set_interface_state("up")

        # Verify Mode
        mode_after = get_mode(interface)
        if mode_after == "Managed":
            log_message("INFO", f"Interface {interface} successfully switched to Managed Mode.")
            click.echo(f"\033[92m[+] Interface {interface} is now in Managed Mode.\033[0m\n")
        else:
            log_message("WARNING", f"Interface {interface} failed to switch to Managed Mode. Current mode: {mode_after}.")
            click.echo(f"\033[91m[WARNING] Interface {interface} did not switch to Managed Mode. Current mode: {mode_after}.\033[0m\n")

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to Managed Mode.")
        click.echo("\033[91m[ERROR] Failed to switch interface to Managed Mode. Check if the interface supports Managed Mode and try again.\033[0m\n", err=True)

# Monitor Mode
def set_monitor_mode():
    """Set the selected wireless interface to Monitor Mode."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to switch to Monitor Mode.")        
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo("\n\033[94m[ Set Monitor Mode ]\033[0m\n")

    try:
        # Check Mode
        if get_mode(interface) == "Monitor":
            log_message("INFO", f"Interface {interface} is already in Monitor Mode. No changes made.")
            click.echo(f"\033[93m[INFO] Interface {interface} is already in Monitor Mode. No changes made.\033[0m\n")
            return

        set_interface_state("down")
        set_mode_type("monitor")
        set_interface_state("up")

        # Verify Mode
        mode_after = get_mode(interface)
        if mode_after == "Monitor":
            log_message("INFO", f"Interface {interface} successfully switched to Monitor Mode.")
            click.echo(f"\033[92m[+] Interface {interface} is now in Monitor Mode.\033[0m\n")
        else:
            log_message("WARNING", f"Interface {interface} failed to switch to Monitor Mode. Current mode: {mode_after}.")
            click.echo(f"\033[91m[WARNING] Interface {interface} did not switch to Monitor Mode. Current mode: {mode_after}.\033[0m\n")

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to Monitor Mode.")
        click.echo("\033[91m[ERROR] Failed to switch interface to Monitor Mode. Check if the interface supports Monitor Mode and try again.\033[0m\n", err=True)

# Reset Interface Driver
def reload_driver(driver):
    """Unload and reload the specified driver."""
    if driver == "Unknown":
        log_message("ERROR", "No valid driver found. Skipping reload.")
        return False

    try:
        log_message("INFO", f"Unloading driver: {driver}")
        subprocess.run(["sudo", "rmmod", driver], check=True)

        time.sleep(2)  # Allow time for the system to process the removal

        log_message("INFO", f"Reloading driver: {driver}")
        subprocess.run(["sudo", "modprobe", driver], check=True)

        log_message("INFO", f"Driver {driver} successfully reloaded.")
        return True  # Success
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to reload driver: {driver}")
        return False  # Failure

# Reset Command
@click.command()
@click.argument("reset_type", type=click.Choice(["soft", "hard"], case_sensitive=False))
def reset_interface(reset_type):
    """Reset the selected wireless interface."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to reset.")
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    log_message("INFO", f"Starting {reset_type} reset for interface {interface}.")
    click.echo("\n\033[94m[ Interface Reset ]\033[0m\n")

    try:
        # Soft Reset
        if reset_type == "soft":
            click.echo(f"\033[94m[INFO] Performing a {reset_type} reset...\033[0m")
            set_interface_state("down")
            click.echo("\033[94m[INFO] Waiting for interface to reinitialise...\033[0m")
            time.sleep(3)  # Delay
            set_interface_state("up")
            log_message("INFO", f"Starting {reset_type} reset for interface {interface}.")            

        # Hard Reset
        elif reset_type == "hard":
            click.echo(f"\033[94m[INFO] Performing a {reset_type} reset...\033[0m")

            # Retrieve Kernel Module Name
            driver = "Unknown"
            try:
                driver_path = subprocess.run(
                    ["readlink", f"/sys/class/net/{interface}/device/driver"],
                    capture_output=True, text=True, check=True
                )
                driver = driver_path.stdout.strip().split("/")[-1]  # Parse
                click.echo("\033[94m[INFO] Waiting for interface to reinitialise...\033[0m")
            except subprocess.CalledProcessError:
                log_message("ERROR", "Failed to retrieve kernel module for interface.")

            if reload_driver(driver):
                log_message("INFO", "Driver reload completed successfully.")
            else:
                log_message("ERROR", "Driver reload failed.")

        # Verify Interface
        timeout = 5  # Delay period
        while timeout > 0:
            if interface in os.listdir("/sys/class/net/"):
                log_message("INFO", f"Interface {interface} successfully reset.")
                click.echo(f"\033[92m[+] Interface {interface} successfully reset.\033[0m")
                break
            time.sleep(1)  # Delay before retry
            timeout -= 1

        if interface not in os.listdir("/sys/class/net/"):
            log_message("ERROR", f"Interface {interface} did not reappear after reset.")
            click.echo("\033[91m[ERROR] Interface did not reappear after driver reload. Please check manually.\033[0m\n")

        # Show & Finish
        mode = get_mode(interface)
        click.echo(f"\033[92m[+] Interface {interface} is in {mode} Mode.\033[0m")
        log_message("INFO", f"{reset_type.capitalize()} Reset Completed for {interface}.")
        click.echo(f"\033[92m[+] {reset_type.capitalize()} Reset Completed for {interface}.\033[0m\n")

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to reset interface {interface}.")
        click.echo("\033[91m[ERROR] Failed to reset the interface. Check permissions and driver status.\033[0m\n", err=True)
