# Wireless Security Testing Toolkit (WSTT)

## Overview
WSTT is the central analysis engine of the toolkit suite. It provides a Python-based, menu-driven command-line interface for managing wireless interfaces, scanning networks, and detecting common security threats through automated packet analysis.

## Engineering Philosophy
- **Hybrid Architecture:** Utilises a "Separation of Concerns" model with a Python front-end for orchestration and Bash back-end for low-level system control.
- **Agile Adaptation:** Originally designed with PyShark, the toolkit was refactored to **Scapy** to ensure parsing reliability and performance under high traffic volumes.
- **Resilient Design:** Features integrated service control for wireless interface management, including monitor mode toggling and hardware resets.

## Key Features
- **Acquisition:** Full or filtered scans via `airodump-ng` and packet dumps via `tcpdump`.
- **Detection Engine:** Automated analysis of `.pcap` files for Deauthentication floods, ARP Spoofing, and Evil Twin attacks.
- **Audit Trails:** Session-based logging in `src/python/logs/` for detailed activity records.

---
## Project Ecosystem
This repository is part of the **Wireless Security Testing Toolkit** suite:
* **[Core Toolkit (WSTT)](https://github.com/paulsmurthwaite/wstt)** — Python/Bash orchestration and analysis engine.
* **[Access Point Toolkit (WAPT)](https://github.com/paulsmurthwaite/wapt)** — Modular tool for launching simulated wireless environments.
* **[Attack Testing Toolkit (WATT)](https://github.com/paulsmurthwaite/watt)** — Configuration and scripts for generating controlled threat scenarios.