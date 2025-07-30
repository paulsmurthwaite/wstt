#!/usr/bin/env python3
"""system.py

Provides a centralized interface for interacting with the operating system.

This module abstracts away the complexities of running external processes,
such as Bash or Python scripts, and querying system information like network
interface status. It is designed to be the single point of contact for all
system-level operations within the WSTT.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import logging
import os
import subprocess

# ─── Local Modules ───
from helpers.output import (
    print_blank,
    print_error,
    print_prompt,
    ui_clear_screen,
    ui_header,
)

log = logging.getLogger(__name__)


def _run_script(command, script_path, script_name, capture_output, pause, clear, title):
    """A private helper to execute a script and handle common UI/error logic."""
    if clear:
        ui_clear_screen()

    if title:
        ui_header(title)
        print_blank()

    if not os.path.exists(script_path):
        print_error(f"Script not found: {os.path.basename(script_path)}")
        log.error("Attempted to run non-existent script: %s", script_path)
        return

    try:
        log.info("Executing script: %s", os.path.basename(script_path))
        subprocess.run(command, check=True, capture_output=capture_output, text=True)
    except subprocess.CalledProcessError as e:
        log.error("Script %s failed with exit code %d.", script_name, e.returncode)
        print_error(f"Script failed during execution: {script_name}")
        # Only print stderr if it was captured
        if capture_output and e.stderr:
            print(e.stderr.strip())

    if pause:
        print_blank()
        print_prompt("Press Enter to return to menu")
        input()


def run_bash_script(script_name, pause=True, capture=True, clear=True, title=None):
    """
    Executes a Bash script located under /src/bash.

    Args:
        script_name (str): Script name without extension.
        pause (bool): Whether to wait for user input after execution.
        capture (bool): If True, captures stdout/stderr. If False, allows
                        the script to print directly to the terminal.
        clear (bool): If True, clears the screen before running.
        title (str, optional): A header to display before execution.
    """
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "bash", f"{script_name}.sh")
    )
    command = ["bash", script_path]
    _run_script(command, script_path, f"{script_name}.sh", capture, pause, clear, title)


def run_python_script(script_name, pause=True, clear=True, title=None):
    """
    Executes a Python script located under /src/python/detect/.

    Args:
        script_name (str): Name of the script without '.py'.
        pause (bool): Whether to wait for user input after execution.
        clear (bool): If True, clears the screen before running.
        title (str, optional): A header to display before execution.
    """
    # Detection scripts are interactive, so we must not capture their output.
    capture_output = False
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "detect", f"{script_name}.py")
    )
    command = ["python3", script_path]
    _run_script(command, script_path, f"{script_name}.py", capture_output, pause, clear, title)


def get_interface_details():
    """
    Gets current network interface details by running a shell script.

    Returns:
        tuple: A tuple containing the interface name (str), state (str),
               and mode (str). Returns a tuple of error messages on failure.
    """
    script_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "bash", "services", "get-current-interface.sh")
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
    """Gets the current network interface name."""
    return get_interface_details()[0]


def get_interface_state():
    """Gets a formatted string of the current network interface state."""
    return f"State:     {get_interface_details()[1]}"


def get_interface_mode():
    """Gets a formatted string of the current network interface mode."""
    return f"Mode:      {get_interface_details()[2]}"