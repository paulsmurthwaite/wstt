#!/usr/bin/env python3
"""wstt_logging.py

Information goes here

Author:      [Your Name]
Date:        [YYYY-MM-DD]
Module:      [Module Code]
"""


import logging
import json
import os

config_file = "wstt_config.json"
log_flag_file = "/tmp/wstt_log_initialised"  # Persistent flag for session-based logging

# Load Configuration
def load_log_config():
    """Load log file path from config file."""
    if not os.path.exists(config_file):
        return "./logs/wstt.log"  # Default log file location

    try:
        with open(config_file, "r") as f:
            config = json.load(f)
            return config.get("log_file", "./logs/wstt.log")  # Use default if missing
    except json.JSONDecodeError:
        return "./logs/wstt.log"  # Default if config is corrupted

# Initialisation
def setup_logger():
    """Initialise logging configuration once per session."""
    log_path = load_log_config()
    log_dir = os.path.dirname(log_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logging.basicConfig(
        filename=log_path,
        filemode="a",  # Append mode
        format="[{asctime}] [{levelname}] {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=logging.INFO  # Default level is INFO
    )

    # Check for startup flag
    if not os.path.exists(log_flag_file):
        logging.info("WSTT Logger initialised. Logging to: %s", log_path)
        open(log_flag_file, "w").close()  # Create the flag file

def log_message(level, message):
    """Log a message with the specified level."""
    setup_logger()  # Logging is configured before logging events

    if level == "INFO":
        logging.info(message)
    elif level == "WARNING":
        logging.warning(message)
    elif level == "ERROR":
        logging.error(message)
        print(f"[ERROR] {message}")  # Print errors to console
    elif level == "CRITICAL":
        logging.critical(message)
        print(f"[CRITICAL] {message}")  # Print critical issues to console
