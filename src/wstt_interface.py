#!/usr/bin/env python3

import click
from wstt_utils import (
    list_interfaces,
    select_interface,
    show_interface,
    set_managed_mode,
    set_monitor_mode,
    reset_interface
)

@click.group()
def cli():
    """Wireless Security Testing Toolkit (WSTT) - Interface Management"""
    pass

# Register CLI commands
cli.add_command(list_interfaces, name="list")
cli.add_command(select_interface, name="select")
cli.add_command(show_interface, name="show")
cli.add_command(set_managed_mode, name="managed")
cli.add_command(set_monitor_mode, name="monitor")
cli.add_command(reset_interface, name="reset")

if __name__ == "__main__":
    cli()
