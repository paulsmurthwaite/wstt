# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [0.5.0] - 2025-03-27
### Added
- `capture_full` function:
  - Prompts for duration or packet count
  - Launches `tcpdump` using `timeout` or `-c`
  - Saves results to `wstt_full-cap-{timestamp}.pcap`
- `capture_filter` function:
  - Parses latest filtered scan CSV for BSSID/channel
  - Prompts for target AP and capture method
  - Sets channel via `iw` and filters using BPF `wlan host <bssid>`
  - Saves results to `wstt_filter-cap-{timestamp}.pcap`
- Shared subprocess runner `run_capture()`
- Wireless channel setter `set_channel()`
- CSV parser `parse_scan_csv()` for reusability
- File lookup helper `get_latest_scan_file()`

### Changed
- Refactored scan and capture logic to ensure:
  - Consistent formatting, prompts, and tabulated AP display
  - Shared interface state checking and directory creation
  - Reuse of helper functions across commands

---

## [0.4.0] - 2025-03-26
### Added
- `scan_filter` function with full support for:
  - Parsing latest full scan CSV
  - Displaying AP selection menu
  - Running filtered scans using `--bssid` and `--channel`
  - Saving results to `wstt_filter-scan-{timestamp}.csv`
- Shared countdown timer via `run_countdown()`
- Shared scan runner via `run_scan()`
- Cleanup utility `cleanup_scan_files()`

### Changed
- `scan_full` now uses `run_countdown()` and `run_scan()` in parallel
- Refactored duplicate subprocess/timer logic into reusable helpers

---

## [0.3.0] - 2025-03-24
### Added
- `scan_full` command:
  - Prompts for scan duration
  - Launches `airodump-ng` with timeout
  - Saves results to `wstt_full-scan-{timestamp}.csv`

### Changed
- Updated `wstt_config.json` with:
  - Scan/capture directories
  - Filename patterns
  - Time control modes
- Refactored logging to initialise via config
- Added real-time countdown to scan duration

---

## [0.2.0] - 2025-03-20
### Added
- CLI command structure using Click:
  - `get`, `set`, `show`, `mode`, `reset`
- Interface mode switching (managed/monitor)
- Interface reset (soft/hard)
- Logging system (`wstt.log`)
- Basic interface status reporting

---

## [0.1.0] - 2025-03-12
### Initial Version
- Project structure and repo scaffolding
- `wstt_interface.py` command parser
- Interface management logic (selection and storage)
- Initial `README.md` and `wstt_config.json` format
