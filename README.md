# Wireless Security Testing Toolkit (WSTT) v0.1-alpha

## NOTE: This Repo supported a final year university project is now archived and no longer maintained ##

## Overview
WSTT is a Python-based toolkit that provides a menu-driven command-line interface for managing wireless interfaces, scanning for networks, capturing traffic, and simulating/detecting common wireless security threats.

The toolkit is designed to be run in a controlled lab environment, simplifying the process of executing complex scenarios and acquiring data for security analysis.

---

## Features
- **Menu-Driven Interface**: A simple, clean UI for accessing all toolkit functions.
- **Acquisition Utilities**:
  - Perform **Full or Filtered Scans** using `airodump-ng`.
  - Capture **Full or Filtered Packet Dumps** using `tcpdump`.
- **Threat Simulation & Detection**:
  - Execute predefined attack scenarios to generate traffic for analysis.
  - Run detection scripts against captured `.pcap` files.
  - Current threats include Deauthentication Floods, ARP Spoofing, Evil Twin attacks, and more.
- **Service Control**:
  - Easily switch a wireless interface between **Managed** and **Monitor** modes.
  - Perform soft/hard resets of the wireless interface.
- **Centralised Configuration**: Key parameters are managed in a central configuration file for consistency.
- **Session Logging**: All actions are logged to a timestamped file in `src/python/logs/` for auditing.

---

## Installation

### 1. System Prerequisites
Install the necessary command-line tools for wireless interaction. 

```bash
sudo apt update
sudo apt install aircrack-ng tcpdump iw iproute2
```

### Clone the repository
```bash
git clone https://github.com/paulsmurthwaite/wstt.git
cd wstt
```

### Make scripts executable
```bash
chmod +x src/python/wstt.py
```

### Python Dependencies
Install the required Python packages. It is highly recommended to use a Python virtual environment.

### Create and activate a virtual environment (optional but recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies
```bash
pip install scapy pyfiglet tabulate
```

---

## Usage
Launch the main toolkit interface from the project's root directory:

```bash
src/python/wstt.py
```

---

## Logging
The toolkit features a robust, session-based logging system designed for auditing and debugging. When the application starts, it creates a new log file for that specific session.

- **Location**: All log files are stored in the `src/python/logs/` directory.
- **Naming**: Each log file is timestamped (e.g., `wstt_log_YYYYMMDD-HHMMSS.log`) to ensure that logs from different sessions are kept separate and easy to find.
- **Content**: The logs capture key user actions, script executions, and any errors that occur, providing a detailed record of each session.

---

## Configuration

WSTT uses a dual-configuration system to separate runtime operational parameters from core application settings.

### Bash Configuration (`src/bash/config/`)
This directory contains `.conf` files that control the behaviour of all Bash scripts, including the acquisition utilities and threat scenarios.

- **`global.conf`**: The primary configuration file. It defines key parameters used by the Scan and Capture utilities, such as the default wireless `INTERFACE`, `DEFAULT_DURATION`, `DEFAULT_CHANNEL`, and `DEFAULT_BSSID`.

- **Scenario-specific configs** (e.g., `t014.conf`): Each threat scenario has its own configuration file to set parameters specific to that simulation, such as target IP addresses or attack duration.

### Python Configuration (`src/python/config/`)

- **`config.json`**: This file configures the Python front-end and analysis engine. It is primarily used to define application-level settings, such as the directory paths for storing logs and packet captures.

---

## **Licence**
This project is licenced under the MIT Licence.

---

## **Author**
- Paul Smurthwaite  
- 12 March 2025  
- TM470-25B
