# WSTT Operator Guide

---

## 1. Overview

The Wireless Security Testing Toolkit (WSTT) is a Python-based toolkit that provides a menu-driven command-line interface for managing wireless interfaces, scanning for networks, capturing traffic, and simulating/detecting common wireless security threats.

The toolkit is designed to be run in a controlled lab environment, simplifying the process of executing complex scenarios and acquiring data for security analysis.

---

## 2. Installation

### System Prerequisites
Install the necessary command-line tools for wireless interaction.

```bash
sudo apt update
sudo apt install aircrack-ng tcpdump iw iproute2
```

### Clone the Repository
```bash
git clone https://github.com/paulsmurthwaite/wstt.git
cd wstt
```

### Make Scripts Executable
```bash
chmod +x src/python/wstt.py
```

### Python Dependencies
Install the required Python packages. It is highly recommended to use a Python virtual environment.

#### Create and activate a virtual environment (optional but recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Install dependencies
```bash
pip install scapy pyfiglet tabulate
```

---

## 3. Usage

Launch the main toolkit interface from the project's root directory:

```bash
sudo ./src/python/wstt.py
```

The main menu provides access to all toolkit functions:
- **Scan Wireless Traffic**: Perform full or filtered network scans to discover devices.
- **Capture Wireless Frames**: Create `.pcap` files of network traffic for analysis.
- **Threat Detection**: Run detection scripts against captured `.pcap` files.
- **Service Control**: Manage the state and mode of your wireless interface.

---

## 4. Threat Detection Scenarios

This section explains how to interpret the results from each detection script available in the "Threat Detection" menu.

### T001 – Unencrypted Traffic Capture
- **Purpose**: Detects clients sending data in cleartext over open (unencrypted) wireless networks.
- **A `POSITIVE` Result Means**: An active data leak is occurring. A client is connected to an open network and is transmitting readable data, making it vulnerable to eavesdropping.

### T002 – Probe Request Snooping
- **Purpose**: Identifies clients broadcasting the names (SSIDs) of wireless networks they have previously connected to.
- **A `POSITIVE` Result Means**: The connection history of one or more client devices has been exposed. This information can be used by an attacker to create a convincing "Evil Twin" or malicious hotspot.

### T003 – SSID Harvesting
- **Purpose**: Detects an unusually high number of unique SSIDs being broadcast in the area.
- **A `POSITIVE` Result Means**: A device is likely using a reconnaissance tool to advertise many fake networks. This can be used to discover client probe requests or to create a confusing environment for users.

### T004 – Evil Twin Attack
- **Purpose**: Detects when a client disconnects from a legitimate AP and reconnects to a rogue AP with the same name (SSID).
- **A `POSITIVE` Result Means**: A Man-in-the-Middle (MitM) attack is in progress. An attacker has successfully lured a client onto a malicious network to intercept its traffic.

### T005 – Open Rogue AP
- **Purpose**: Identifies clients communicating over an open network, framed in the context of a malicious rogue device.
- **A `POSITIVE` Result Means**: A client has likely connected to a malicious honeypot AP. This is a strong indicator of a MitM attack where the attacker's goal is to eavesdrop on the client's traffic.

### T006 – Misconfigured Access Point
- **Purpose**: Audits all detected APs and flags any that are using weak or no encryption (Open, WEP, or WPA1).
- **A `POSITIVE` Result Means**: A significant security vulnerability exists. The identified networks are easy targets for eavesdropping and other attacks and should be reconfigured immediately.

### T007 – Deauthentication Flood
- **Purpose**: Detects an abnormally high volume of deauthentication frames targeting a client or an entire network.
- **A `POSITIVE` Result Means**: An active Denial of Service (DoS) attack is underway, intended to forcibly disconnect users from the wireless network. This is often a precursor to an Evil Twin attack.

### T008 – Beacon Flood
- **Purpose**: Detects an abnormally high volume and variety of Beacon frames.
- **A `POSITIVE` Result Means**: An active DoS attack is underway. The attacker is polluting the airwaves with fake network advertisements to disrupt network discovery and overwhelm client devices.

### T009 – Authentication Flood
- **Purpose**: Detects an abnormally high volume of authentication frames sent to a single Access Point.
- **A `POSITIVE` Result Means**: An active DoS attack is targeting a specific piece of network infrastructure. The goal is to overwhelm the AP, preventing legitimate users from connecting.

### T014 – ARP Spoofing
- **Purpose**: Detects contradictory ARP replies on the network, where two different MAC addresses claim the same IP address.
- **A `POSITIVE` Result Means**: An active MitM attack is underway on the wired/wireless network. An attacker is redirecting traffic through their own machine to intercept or manipulate it.

### T015 – Malicious Hotspot Auto-Connect
- **Purpose**: Detects a client connecting to and passing traffic over an open network that is impersonating a common public hotspot.
- **A `POSITIVE` Result Means**: A successful MitM attack has occurred by exploiting a client's insecure auto-connect settings. The client's traffic is being intercepted.

### T016 – Directed Probe Response
- **Purpose**: Identifies an AP sending a targeted response to a client's probe for a specific network.
- **A `POSITIVE` Result Means**: An attempt to lure a client onto a potentially malicious network has been detected. The "Notes" column in the summary provides context to help determine if the responding AP is legitimate.
