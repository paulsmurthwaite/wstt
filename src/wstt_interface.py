#!/usr/bin/env python3
"""wstt_interface.py

Wireless interface management using Aircrack-ng suite

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      TM470-25B
"""

import click
import json
import os
import subprocess
from tabulate import tabulate

config_file = "wstt_config.json"

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

def save_config(config):
    """Save the configuration to JSON file."""
    with open(config_file, "w") as f:
        json.dump(config, f, indent=4)

@click.group()
@click.pass_context
def cli(ctx):
    """Wireless Security Testing Toolkit (WSTT) - Interface Management"""
    ctx.ensure_object(dict)  # Ensures ctx.obj is always a dictionary

@click.command()
def list_interfaces():
    """List available wireless interfaces using airmon-ng"""
    try:
        result = subprocess.run(["sudo", "airmon-ng"], capture_output=True, text=True, check=True)
        if result.stdout.strip():
            click.echo(result.stdout)
        else:
            click.echo("[ERROR] No wireless interfaces found.", err=True)
    except subprocess.CalledProcessError:
        click.echo("[ERROR] Failed to retrieve wireless interfaces. Ensure Aircrack-ng is installed and run with sudo.", err=True)

@click.command()
@click.pass_context
def select_interface(ctx):
    """List available interfaces using airmon-ng and allow the user to select one."""
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

def get_selected_interface():
    """Retrieve the selected interface from the JSON config file."""
    config = load_config()
    return config.get("interface", None)

import click
import subprocess
import json
from tabulate import tabulate

@click.command()
def show_interface():
    """Show the currently selected wireless interface along with status, mode, driver, and chipset."""
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

@click.command()
def check_status():
    """Check the current mode and status of the selected wireless interface"""
    interface = get_selected_interface()

    if not interface:
        click.echo("\033[91m[ERROR] No interface selected. Please run 'wstt_interface.py select' first.\033[0m")
        return

    click.echo(f"Checking status of interface: \033[94m{interface}\033[0m")

    try:
        # Run iw command to get interface info
        result = subprocess.run(["iw", "dev", interface, "info"], capture_output=True, text=True, check=True)

        mode = "Unknown"
        is_up = "Unknown"

        # Parse output to extract mode and state
        for line in result.stdout.split("\n"):
            if "type" in line:
                mode = line.split()[-1].capitalize()  # Converts 'managed' → 'Managed'
            if f"Interface {interface}" in line:
                is_up = "Up"  # If interface appears in iw output, it's UP

        click.echo(f"Mode: \033[92m{mode}\033[0m")  # Green text
        click.echo(f"State: \033[92m{is_up}\033[0m")  # Green text

    except subprocess.CalledProcessError:
        click.echo("\033[91m[ERROR] Failed to retrieve interface status. Ensure iw is installed.\033[0m", err=True)

cli.add_command(list_interfaces, name="list")
cli.add_command(show_interface, name="show")
cli.add_command(select_interface, name="select")
cli.add_command(check_status, name="status")

if __name__ == "__main__":
    cli()
