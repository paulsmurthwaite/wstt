# WSTT Developer Guide

---

## 1. Project Architecture Overview

The Wireless Security Testing Toolkit (WSTT) is built on a dual-component architecture:

- **Bash Back-End**: A collection of robust shell scripts responsible for all direct interaction with the operating system and wireless hardware. This includes managing the network interface, running `airodump-ng` and `tcpdump`, and executing threat simulation tools.
- **Python Front-End**: A Python application that provides the user interface, orchestrates the execution of the Bash scripts, and runs the powerful analysis engine for threat detection.

This separation ensures that low-level system commands are kept distinct from the higher-level application logic and analysis.

---

## 2. Bash Scripting Architecture

The Bash scripts are organised into a modular structure within the `src/bash/` directory.

### `config/`
This directory holds all configuration files for the Bash scripts.
- **`global.conf`**: Defines system-wide defaults, most importantly the target `INTERFACE`.
- **Scenario-specific `.conf` files** (e.g., `t004.conf`): Contain parameters for individual threat scenarios, such as target BSSIDs or attack durations.

### `helpers/`
Contains reusable shell functions sourced by other scripts to ensure consistency.
- **`fn_print.sh`**: Provides standardised, coloured output functions.
- **`fn_mode.sh`**: Handles the logic for putting the wireless interface into monitor mode.

### `utilities/`
These are the primary scripts for data acquisition.
- **`wstt_scan.sh`**: The core scanning utility, wrapping `airodump-ng`.
- **`wstt_capture.sh`**: The core capture utility, wrapping `tcpdump`.

### `services/`
These scripts are responsible for managing the state of the wireless interface (e.g., `ifconfig up/down`, `iw dev ... set type monitor`).

---

## 3. Python Architecture

The Python application (`src/python/`) acts as the brain of the toolkit.

### Main Entry Point (`wstt.py`)
This is the main executable. It performs pre-flight checks, initialises the logger, and runs the main menu loop that drives the user interface.

### Helpers (`helpers/`)
This directory contains modules that provide core functionality to the rest of the application.
- **`ui.py`**: Renders all menus and user interface elements.
- **`system.py`**: The sole interface for executing the Bash back-end scripts.
- **`analysis.py`**: The core analysis engine (see below).

### Detection Scripts (`detect/`)
Each script in this directory corresponds to a specific threat scenario (e.g., `t004.py`). These scripts are pure orchestrators:
1. They prompt the user to select a `.pcap` file.
2. They call the `analyse_capture` function to process the file.
3. They call a specific detection function (e.g., `detect_rogue_aps_context`).
4. They format and present the results to the user.

### Core Analysis Engine (`helpers/analysis.py`)

This is the most critical component of the Python architecture. It is designed around a **single-pass analysis** model. The `analyse_capture` function iterates through a packet capture file *once*, sorting every relevant frame into a structured dictionary called the `context`.

This `context` object is then passed to the various detection functions. This approach is highly efficient, as it avoids re-reading and re-parsing the capture file for every single detection.

#### API Reference Example: `analyse_capture`

The following is the docstring for the main analysis function, demonstrating how the API is documented within the code.

```python
def analyse_capture(packets):
    """
    Performs a single pass over packets to build a network analysis context.

    Args:
        packets (scapy.plist.PacketList): A list of Scapy packets from a capture file.

    Returns:
        dict: A comprehensive context dictionary containing structured data about
              access points, traffic, and key network events.
    """
```
