# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1] - 2025-05-17

### Added
- Initial version of the Wireless Security Testing Toolkit (WSTT).
- Menu-driven interface for core functionalities.
- Centralised logging for application events.
- Standardised UI components for consistent output.
- Helper scripts for managing wireless interface state and mode.

### Changed
- Refactored `Scan` and `Capture` utilities into non-interactive, menu-driven tools for improved usability and consistency.
- Centralised all default configuration parameters (duration, channel, BSSID) into `global.conf`.
- Standardised user confirmation prompts across all utilities, with improved exit handling.
- Replaced `bettercap` with the more reliable `arpspoof` for the T014 scenario.
