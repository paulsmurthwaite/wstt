#!/usr/bin/env python3
"""Filename goes here

Information goes here

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      [Module Code]
"""


import click
from wstt_utils import (
    get_interfaces,
    set_interface,
    show_interface,
    set_mode,
    reset_interface,
    scan_interface
)

@click.group()
def cli():
    """Wireless Security Testing Toolkit (WSTT) - Interface Management"""
    pass

# Register CLI commands
cli.add_command(get_interfaces, name="get")
cli.add_command(set_interface, name="set")
cli.add_command(show_interface, name="show")
cli.add_command(set_mode, name="mode")
cli.add_command(reset_interface, name="reset")
cli.add_command(scan_interface, name="scan")

if __name__ == "__main__":
    cli()
