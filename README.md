# Wireless Security Testing Toolkit (WSTT)

## **Overview**
WSTT provides a modular command-line interface for managing wireless interfaces, enabling monitor mode, scanning for access points, capturing traffic, and detecting wireless security threats.

The toolkit simplifies the process of switching between **managed** and **monitor** modes, scanning for wireless traffic, and analysing common wireless attacks through automated detection scripts.

---

## **Features**
- Enable **Monitor Mode** and **Managed Mode**
- **Soft/Hard Reset** wireless interfaces
- View and select available wireless interfaces
- Perform **Full or Filtered Scans** using `airodump-ng`
- Capture **Full or Filtered Packet Dumps** using `tcpdump`
- Automatically detect threats in `.pcap` and `.csv` files:
  - T001: Unencrypted Traffic
  - T002: Probe Request Snooping
  - T003: SSID Harvesting
  - T004: Evil Twin AP
  - T005: Open Rogue AP
  - T006: Misconfigured AP
  - T007: Deauthentication Flood
  - T008: Beacon Flood
  - T009: Authentication Flood
  - T014: ARP Spoofing
  - T015: Malicious Hotspot Auto-Connect
  - T016: Directed Probe Response
- All detection scripts include:
  - **Basic Detection Mode** (CLI/Bash)
  - Placeholder for **Advanced Detection Mode** (Python)

---

## **Installation**
### **Prerequisites**
```bash
sudo apt update
sudo apt install iw iproute2 aircrack-ng tshark tcpdump
```

### Clone the repository
```bash
git clone https://github.com/your-repo/wstt.git
cd wstt
```

### Make scripts executable
```bash
chmod +x scripts/*.sh
chmod +x helpers/*.sh
```

---

## **Usage Overview**
Run capture or scan scripts from the `scripts/` directory:

```bash
./scripts/scan.sh       # Full or filtered scan
./scripts/capture.sh    # Full or filtered packet capture
./scripts/detect_t001.sh  # Run specific threat detection (e.g. T001)
```

---

## **Detection Modes**
Each detection script supports:
- `[1] Basic`: Lightweight Bash-based detection
- `[2] Advanced`: Placeholder for Python-based analysis

Files are auto-selected based on recency, or prompted when multiple exist.

---

## **Logging**
All key events and actions are logged to `wstt.log` (optional).  
Manual review of scan and capture artefacts is also supported via detection scripts.

---

## **Configuration**
WSTT uses `config.sh` to set:
- `INTERFACE` (e.g. wlan0mon)
- `CAP_DIR`, `SCN_DIR` for output
- Default durations and naming conventions

---

## **Licence**
This project is licenced under the MIT Licence.

---

## **Author**
- Paul Smurthwaite  
- 12 March 2025  
- TM470-25B
