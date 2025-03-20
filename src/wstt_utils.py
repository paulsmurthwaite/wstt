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

# Default Configuration
default_config = {
    "interface": None,
    "log_file": "./logs/wstt.log",  # Default log location
    "colors": {
        "success": "\\033[92m",
        "info": "\\033[90m",
        "warning": "\\033[93m",
        "error": "\\033[91m",
        "title": "\\033[1;94m",
        "reset": "\\033[0m"
    }
}

# Load Configuration
def load_config():
    """Load configuration from JSON file, creating it if missing."""
    if not os.path.exists(config_file):
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)

    try:
        with open(config_file, "r") as f:
            config = json.load(f)

        # Ensure all keys are added
        for key, value in default_config.items():
            if key not in config:
                config[key] = value

        return config

    except json.JSONDecodeError:
        # If the file is corrupted, reset it
        with open(config_file, "w") as f:
            json.dump(default_config, f, indent=4)
        return default_config

# Save Configuration
def save_config(config):
    """Save the configuration to JSON file."""
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

# Text Decoration Configuration
def format_message(message_type, message):
    """Format a message with ANSI color codes from config.
    
    - `message_type`: "error", "info", "success", "title", etc.
    - `message`: The actual text to format.
    """
    colors = load_config().get("colors", {})
    color = colors.get(message_type, colors.get("reset", "\\033[0m"))  # Use raw string from JSON
    color = color.replace("\\033", "\033")  # Convert to actual ANSI escape sequence
    reset = colors.get('reset', "\\033[0m").replace("\\033", "\033")  # Ensure reset works correctly

    # Dictionary lookup for message formatting
    message_formats = {
        "error": f"[ERROR] {message}",
        "warning": f"[WARNING] {message}",
        "info": f"[INFO] {message}",
        "success": f"[+] {message}",
        "title": f"\n[ {message} ]"
    }

    # Retrieve message from dictionary
    formatted_message = message_formats.get(message_type, message)

    return "{}{}{}".format(color, formatted_message, reset)

# Get Selected Interface
def get_selected_interface():
    """Retrieve the selected interface from the config file."""
    config = load_config()
    return config.get("interface", None)

# List Interfaces
@click.command()
def get_interfaces():
    """List available wireless interfaces."""

    click.echo(format_message("title", "Available Interfaces"))

    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            click.echo(result.stdout)
        else:
            log_message("WARNING", "No wireless interfaces found.")
            click.echo(format_message("error", "No wireless interfaces found."))
    except subprocess.CalledProcessError:
        log_message("ERROR", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?")
        click.echo(format_message("error", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?"))

# Set Interface
@click.command()
@click.pass_context
def set_interface(ctx):
    """Select from a list of available interfaces."""
    click.echo(format_message("title", "Select Interface"))

    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if not result.stdout.strip():
            log_message("WARNING", "No wireless interfaces found when attempting to set an interface.")
            click.echo(format_message("error", "No wireless interfaces found."))
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
        click.echo(format_message("success", f"Selected interface: {selected_interface}"))

    except subprocess.CalledProcessError:
        log_message("ERROR", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?")
        click.echo(format_message("error", "Failed to retrieve wireless interfaces.  Is Aircrack-ng installed?"))

# Show Interface
@click.command()
def show_interface():
    """Show the currently selected wireless interface details."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to display interface details.")
        click.echo(format_message("error", "No interface selected. Please run 'wstt_interface.py set"))
        return

    click.echo(format_message("title", "Current Interface"))
    click.echo()  # Blank line

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
        click.echo(format_message("error", "Failed to retrieve interface details.  Are 'ip', 'iw', 'airmon-ng', and 'lshw' installed?"))

# Set Interface State
def set_interface_state(state):
    """Bring the selected wireless interface UP or DOWN."""
    interface = get_selected_interface()
    if not interface:
        log_message("WARNING", "No interface selected when attempting to bring interface UP/DOWN.")
        click.echo(format_message("error", "No interface selected."))
        return

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, state], check=True)
        log_message("INFO", f"Interface {interface} set to {state}.")
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to bring interface {interface} {state}.")
        click.echo(format_message("error", f"Failed to bring the interface {state}."))

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
        click.echo(format_message("error", "No interface selected."))
        return

    try:
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", mode_type], check=True)
        log_message("INFO", f"Interface {interface} mode changed to {mode_type}.")
    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to {mode_type} Mode.")
        click.echo(format_message("error", f"Failed to switch interface to {mode_type} Mode."))

# Managed Mode
def set_managed_mode():
    """Set the selected wireless interface to Managed Mode."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to switch to Managed Mode.")
        click.echo(format_message("error", "No interface selected. Please run 'wstt_interface.py set"))
        return

    click.echo(format_message("title", "Set Managed Mode"))

    try:
        # Get Mode
        if get_mode(interface) == "Managed":
            log_message("INFO", f"Interface {interface} is already in Managed Mode. No changes made.")
            click.echo(format_message("info", f"Interface {interface} is already in Managed Mode. No changes made."))
            return

        set_interface_state("down")
        set_mode_type("managed")
        set_interface_state("up")

        # Verify Mode
        mode_after = get_mode(interface)
        if mode_after == "Managed":
            log_message("INFO", f"Interface {interface} successfully switched to Managed Mode.")
            click.echo(format_message("success", f"Interface {interface} is now in Managed Mode."))
        else:
            log_message("WARNING", f"Interface {interface} failed to switch to Managed Mode. Current mode: {mode_after}.")
            click.echo(format_message("warning", f"Interface {interface} did not switch to Managed Mode. Current mode: {mode_after}."))

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to Managed Mode.")
        click.echo(format_message("error", "Failed to switch interface to Managed Mode. Check if the interface supports Managed Mode and try again."))

# Monitor Mode
def set_monitor_mode():
    """Set the selected wireless interface to Monitor Mode."""
    interface = get_selected_interface()

    if not interface:
        log_message("WARNING", "No interface selected when attempting to switch to Monitor Mode.")        
        click.echo(format_message("error", "No interface selected. Please run 'wstt_interface.py set"))
        return

    click.echo(format_message("title", "Set Monitor Mode"))

    try:
        # Check Mode
        if get_mode(interface) == "Monitor":
            log_message("INFO", f"Interface {interface} is already in Monitor Mode. No changes made.")
            click.echo(format_message("info", f"Interface {interface} is already in Monitor Mode. No changes made."))
            return

        set_interface_state("down")
        set_mode_type("monitor")
        set_interface_state("up")

        # Verify Mode
        mode_after = get_mode(interface)
        if mode_after == "Monitor":
            log_message("INFO", f"Interface {interface} successfully switched to Monitor Mode.")
            click.echo(format_message("success", f"Interface {interface} is now in Monitor Mode."))
        else:
            log_message("WARNING", f"Interface {interface} failed to switch to Monitor Mode. Current mode: {mode_after}.")
            click.echo(format_message("warning", f"Interface {interface} did not switch to Monitor Mode. Current mode: {mode_after}."))

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to switch interface {interface} to Monitor Mode.")
        click.echo(format_message("error", "Failed to switch interface to Managed Mode. Check if the interface supports Monitor Mode and try again."))

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
        click.echo(format_message("error", "No interface selected. Please run 'wstt_interface.py set"))
        return

    log_message("INFO", f"Starting {reset_type} reset for interface {interface}.")
    click.echo(format_message("title", "Interface Reset"))

    try:
        # Soft Reset
        if reset_type == "soft":
            click.echo(format_message("info", f"Performing a {reset_type} reset..."))
            set_interface_state("down")
            click.echo(format_message("info", "Waiting for interface to reinitialise..."))
            time.sleep(3)  # Delay
            set_interface_state("up")
            log_message("INFO", f"Starting {reset_type} reset for interface {interface}.")            

        # Hard Reset
        elif reset_type == "hard":
            click.echo(format_message("info", f"Performing a {reset_type} reset..."))

            # Retrieve Kernel Module Name
            driver = "Unknown"
            try:
                driver_path = subprocess.run(
                    ["readlink", f"/sys/class/net/{interface}/device/driver"],
                    capture_output=True, text=True, check=True
                )
                driver = driver_path.stdout.strip().split("/")[-1]  # Parse
                click.echo(format_message("info", "Waiting for interface to reinitialise..."))
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
                click.echo(format_message("success", f"Interface {interface} successfully reset."))
                break
            time.sleep(1)  # Delay before retry
            timeout -= 1

        if interface not in os.listdir("/sys/class/net/"):
            log_message("ERROR", f"Interface {interface} did not reappear after reset.")
            click.echo(format_message("error", "Interface did not reappear after driver reload. Please check manually."))

        # Show & Finish
        mode = get_mode(interface)
        click.echo(format_message("success", f"Interface {interface} is in {mode} Mode."))
        log_message("INFO", f"{reset_type.capitalize()} Reset Completed for {interface}.")
        click.echo(format_message("success", f"{reset_type.capitalize()} Reset Completed for {interface}."))

    except subprocess.CalledProcessError:
        log_message("ERROR", f"Failed to reset interface {interface}.")
        click.echo(format_message("error", "Failed to reset the interface. Check permissions and driver status."))
