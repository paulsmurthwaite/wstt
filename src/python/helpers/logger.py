#!/usr/bin/env python3
"""logger.py

Provides a centralised, structured logging utility for the WSTT.

This module uses Python's built-in `logging` library to create a robust,
file-based logger. It is designed to be initialised once per application run,
creating a timestamped log file for each session. This separates application
event logging from user-facing terminal output.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
import logging
import os
from datetime import datetime

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))

def setup_logger(log_prefix="wstt"):
    """
    Sets up a structured, file-based logger for a WSTT session.

    This function creates a new log file for each session, named with a
    timestamp. It configures the logger to write messages in a structured
    format. This should be called once at the start of an application run.

    Args:
        log_prefix (str): A prefix for the log file name (e.g., 't004', 'main').
                          Defaults to 'wstt'.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    log_filename = os.path.join(LOG_DIR, f"{log_prefix}-{timestamp}.log")

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()

    file_handler = logging.FileHandler(log_filename, mode='w', encoding='utf-8')
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(levelname)-8s - %(name)-20s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.info("Logger initialised. Logging session to: %s", os.path.basename(log_filename))