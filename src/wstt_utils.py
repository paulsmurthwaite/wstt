#!/usr/bin/env python3

import click
import json
import os
import subprocess
import time
from tabulate import tabulate

config_file = "wstt_config.json"

# Load configuration
def load_config():
    """Load configuration from JSON file, creating it if missing."""
    if not os.path.exists(config_file):
        # Create default config if file doesn't exist
        with open(config_file, "w") as f:
            json.dump({}, f, indent=4)

    try:
        with open(config_file, "r") as f:
            return json.load(f)  # Load the existing config
    except json.JSONDecodeError:
        # If the file is corrupted, reset it
        with open(config_file, "w") as f:
            json.dump({}, f, indent=4)
        return {}

# Save configuration
def save_config(config):
    """Save the configuration to JSON file."""
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

# Retrieve selected interface
def get_selected_interface():
    """Retrieve the selected interface from the config file."""
    config = load_config()
    return config.get("interface", None)

# List interfaces
@click.command()
def list_interfaces():
    """List available wireless interfaces."""
    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            click.echo(result.stdout)
        else:
            click.echo("[ERROR] No wireless interfaces found.", err=True)
    except subprocess.CalledProcessError:
        click.echo("[ERROR] Failed to retrieve wireless interfaces. Ensure Aircrack-ng is installed and run with sudo.", err=True)

# Select interface
@click.command()
@click.pass_context
def select_interface(ctx):
    """Select from a list of available interfaces."""
    click.echo("\nScanning for available wireless interfaces...\n")

    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if not result.stdout.strip():
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

        click.echo(f"\n\033[92m[+] Selected interface: {selected_interface}\033[0m")

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to retrieve wireless interfaces. Ensure Aircrack-ng is installed.\033[0m", err=True)

# Show interface details
@click.command()
def show_interface():
    """Show the currently selected wireless interface details."""
    interface = get_selected_interface()

    if not interface:
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo("\n\033[94m[ WSTT - Interface Details ]\033[0m\n")  # Blue heading

    try:
        # Get MAC Address & Interface State (UP/DOWN)
        mac_address, state = "Unknown", "Unknown"
        ip_result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True, check=True)
        for line in ip_result.stdout.split("\n"):
            if "link/ether" in line:
                mac_address = line.split()[1]  # Extract MAC Address
            if "state" in line:
                state = line.split("state")[1].split()[0].capitalize()  # Extract UP/DOWN state

        # Get Interface Mode (Managed/Monitor)
        mode = "Unknown"
        iw_result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Extract Managed/Monitor mode

        # Get Driver from lshw
        driver = "Unknown"
        lshw_result = subprocess.run(["sudo", "lshw", "-C", "network"], capture_output=True, text=True, check=True)
        in_block = False
        for line in lshw_result.stdout.split("\n"):
            if interface in line:
                in_block = True  # Inside the block for the correct interface
            if in_block:
                if "driver=" in line:
                    driver = line.split("driver=")[-1].split()[0]  # Extract driver
            if line.strip() == "":  # End of block
                in_block = False

        # Get Chipset & Capabilities from airmon-ng
        chipset, capabilities = "Unknown", "Unknown"
        airmon_result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        for line in airmon_result.stdout.split("\n"):
            columns = line.split()
            if len(columns) >= 4 and columns[1] == interface:
                chipset = " ".join(columns[3:])  # Extract Chipset from last column
                capabilities = columns[3]  # Extract Capabilities (802.11a/b/g/n/ac)

        # Format output using tabulate with "plain" style for Cisco-like output
        table_data = [[interface, mac_address, state, mode, driver, chipset]]
        headers = ["Interface", "MAC Address", "State", "Mode", "Driver", "Chipset"]
        table = tabulate(table_data, headers=headers, tablefmt="plain")

        click.echo(table)
        click.echo()  # Ensure a blank line before returning to command prompt

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to retrieve interface details. Ensure 'ip', 'iw', 'airmon-ng', and 'lshw' are installed.\033[0m", err=True)

# Bring Interface down
def bring_interface_down():
    """Bring the selected wireless interface DOWN (internal use only)."""
    interface = get_selected_interface()
    if not interface:
        click.echo("\033[91m[ERROR] No interface selected.\033[0m")
        return

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "down"], check=True)
        click.echo(f"\033[92m[+] Interface {interface} is now DOWN.\033[0m")
    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to bring the interface down.\033[0m", err=True)

# Bring Interface up
def bring_interface_up():
    """Bring the selected wireless interface UP (internal use only)."""
    interface = get_selected_interface()
    if not interface:
        click.echo("\033[91m[ERROR] No interface selected.\033[0m")
        return

    try:
        subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)
        click.echo(f"\033[92m[+] Interface {interface} is now UP.\033[0m")
    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to bring the interface up.\033[0m", err=True)

# Set Managed mode
@click.command()
def set_managed_mode():
    """Set the selected wireless interface to Managed Mode."""
    interface = get_selected_interface()

    if not interface:
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo(f"\n\033[94m[INFO] Switching interface {interface} to Managed Mode...\033[0m")

    try:
        # Check current mode before changing
        mode = "Unknown"
        iw_result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Extract Managed/Monitor mode

        if mode == "Managed":
            click.echo(f"\033[93m[INFO] Interface {interface} is already in Managed Mode. No changes made.\033[0m")
            return

        bring_interface_down()
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "managed"], check=True)
        bring_interface_up()

        # Verify mode change again
        mode_after = "Unknown"
        iw_result_after = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result_after.stdout.split("\n"):
            if "type" in line:
                mode_after = line.split()[-1].capitalize()

        if mode_after == "Managed":
            click.echo(f"\033[92m[+] Interface {interface} is now in Managed Mode.\033[0m")
        else:
            click.echo(f"\033[91m[WARNING] Interface {interface} did not switch to Managed Mode. Current mode: {mode_after}.\033[0m")

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to switch interface to Managed Mode. Check if the interface supports Managed Mode and try again.\033[0m", err=True)

# Set Monitor mode
@click.command()
def set_monitor_mode():
    """Set the selected wireless interface to Monitor Mode."""
    interface = get_selected_interface()

    if not interface:
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo(f"\n\033[94m[INFO] Switching interface {interface} to Monitor Mode...\033[0m")

    try:
        # Check current mode before changing
        mode = "Unknown"
        iw_result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Extract Managed/Monitor mode
        
        if mode == "Monitor":
            click.echo(f"\033[93m[INFO] Interface {interface} is already in Monitor Mode. No changes made.\033[0m")
            return

        bring_interface_down()
        subprocess.run(["sudo", "iw", "dev", interface, "set", "type", "monitor"], check=True)
        bring_interface_up()

        # Verify mode change again
        mode_after = "Unknown"
        iw_result_after = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result_after.stdout.split("\n"):
            if "type" in line:
                mode_after = line.split()[-1].capitalize()

        if mode_after == "Monitor":
            click.echo(f"\033[92m[+] Interface {interface} is now in Monitor Mode.\033[0m")
        else:
            click.echo(f"\033[91m[WARNING] Interface {interface} did not switch to Monitor Mode. Current mode: {mode_after}.\033[0m")

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to switch interface to Monitor Mode. Check if the interface supports Monitor Mode and try again.\033[0m", err=True)

# Reset Interface (Soft/Hard)
@click.command()
@click.argument("reset_type", type=click.Choice(["soft", "hard"], case_sensitive=False))
def reset_interface(reset_type):
    """Reset the selected wireless interface.

    reset soft: Bring interface DOWN, restore mode, bring interface UP.
    reset hard: Perform a soft reset, unload & reload driver, restore mode.
    """
    interface = get_selected_interface()

    if not interface:
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo(f"\n\033[94m[INFO] Performing a {reset_type.upper()} reset on {interface}...\033[0m")

    try:
        # Step 1: Get the current mode (Managed/Monitor)
        mode = "Unknown"
        iw_result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)
        for line in iw_result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Extract Managed/Monitor mode

        click.echo(f"\033[94m[INFO] Current Mode: {mode}\033[0m")

        # Step 2: Perform a Soft Reset (Down > Restore Mode > Up)
        bring_interface_down()
        bring_interface_up()

        # Step 3: If Hard Reset, Unload & Reload the Driver
        if reset_type == "hard":
            click.echo("\033[94m[INFO] Performing a full driver reset...\033[0m")

            # Retrieve Kernel Module (Driver) Name
            driver = "Unknown"
            try:
                driver_path = subprocess.run(["readlink", f"/sys/class/net/{interface}/device/driver"], capture_output=True, text=True, check=True)
                driver = driver_path.stdout.strip().split("/")[-1]
            except subprocess.CalledProcessError:
                click.echo("\033[91m[ERROR] Failed to retrieve kernel module for interface.\033[0m")

            if driver != "Unknown":
                try:
                    subprocess.run(["sudo", "rmmod", driver], check=True)
                    click.echo(f"\033[92m[+] Driver {driver} unloaded successfully.\033[0m")

                    subprocess.run(["sudo", "modprobe", driver], check=True)
                    click.echo(f"\033[92m[+] Driver {driver} reloaded successfully.\033[0m")
                except subprocess.CalledProcessError:
                    click.echo("\033[91m[ERROR] Failed to reload the driver.\033[0m")

        # Step 4: Wait for the interface to reappear after driver reload
        click.echo(f"\033[94m[INFO] Waiting for {interface} to reinitialize...\033[0m")
        time.sleep(3)  # Short delay to allow the kernel to reload the interface

        # Verify the interface exists before proceeding
        if not os.path.exists(f"/sys/class/net/{interface}"):
            click.echo("\033[91m[ERROR] Interface did not reappear after driver reload. Please check manually.\033[0m")
            return

        # Restore Original Mode (Managed/Monitor)
        if mode == "Managed":
            set_managed_mode.invoke(click.Context(set_managed_mode))
        elif mode == "Monitor":
            set_monitor_mode.invoke(click.Context(set_monitor_mode))

        click.echo(f"\033[92m[+] {reset_type.capitalize()} Reset Completed for {interface}.\033[0m")

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to reset the interface. Check permissions and driver status.\033[0m", err=True)
