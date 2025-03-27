# Wireless Security Testing Toolkit (WSTT)

## **Overview**
WSTT provides a modular command-line interface for managing wireless interfaces, enabling monitor mode, scanning for access points, and performing filtered or full wireless scans and packet captures.

The toolkit simplifies the process of switching between **managed** and **monitor** modes, resetting interfaces, performing wireless traffic scans, and preparing for further analysis or capture.

---

## **Features**
- Enable **Monitor Mode** for wireless packet scanning  
- Enable **Managed Mode** for normal Wi-Fi operation  
- **Reset Wireless Interface** (soft or hard reset options)  
- **Check Current Interface Details**  
- Perform **Full Wireless Scans** with output saved to `.csv`  
- Perform **Filtered Wireless Scans** (by BSSID and channel) using previously captured data  
- Output filenames and directories are configurable via `wstt_config.json`  
- Real-time countdown display for scans  
- Logging of all scan actions and errors to `wstt.log`

---

## **Installation**
### **Prerequisites**
Before using WSTT, ensure you have the required dependencies installed:
```bash
sudo apt update
sudo apt install iw iproute2 aircrack-ng
```

### Clone the repository
```bash
git clone https://github.com/your-repo/wstt.git
cd wstt
```

### Make the script executable
```bash
chmod +x wstt_interface.py
```

---

## **Usage**
WSTT uses subcommands and interactive prompts.  
Run the main script with one of the following commands:

### View Available Interfaces
```bash
./wstt_interface.py get
```

### Set Wireless Interface
```bash
./wstt_interface.py set
```

### Show Current Interface Details
```bash
./wstt_interface.py show
```

### Set Interface Mode
```bash
./wstt_interface.py mode managed
./wstt_interface.py mode monitor
```

### Reset Interface
```bash
./wstt_interface.py reset soft
./wstt_interface.py reset hard
```

### Perform Full Scan (All Wireless Traffic)
```bash
./wstt_interface.py scan full
```
- Prompts for scan duration
- Saves results to `./scans/wstt_full-scan-<timestamp>.csv`

### Perform Filtered Scan (Targeted by BSSID/Channel)
```bash
./wstt_interface.py scan filter
```
- Parses latest full scan file
- Lets you select an AP (BSSID and channel)
- Prompts for duration
- Saves results to `./scans/wstt_filter-scan-<timestamp>.csv`

---

## **Logging**
All actions and errors are logged to `wstt.log` (path defined in `wstt_config.json`):
```bash
tail -f logs/wstt.log
```

---

## **Configuration**
WSTT uses a JSON-based configuration file: `wstt_config.json`

Example entries:
```json
"scan_directory": "./scans/",
"capture_directory": "./caps/",
"file_naming": {
  "full_scan": "wstt_full-scan-{timestamp}.csv",
  "filter_scan": "wstt_filter-scan-{timestamp}.csv",
  "full_cap": "wstt_full-cap-{timestamp}.pcap",
  "filter_cap": "wstt_filter-cap-{timestamp}.pcap"
}
```

---

## **Licence**
This project is licenced under the MIT Licence.

---

## **Author**
- Paul Smurthwaite  
- 12 March 2025  
- TM470-25B
