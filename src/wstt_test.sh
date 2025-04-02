#!/bin/bash
LOGFILE="logs/wstt.log"

echo "[+] Clearing previous logs..."
> $LOGFILE  # Clears the log file

echo "[+] Running interface test...(Get Interface Information)"
python3 wstt_interface.py get

echo "[+] Running interface test...(Soft Reset)"
python3 wstt_interface.py reset soft

echo "[+] Running interface test...(Hard Reset)"
python3 wstt_interface.py reset hard

echo "[+] Running interface test...(Enable Monitor Mode)"
python3 wstt_interface.py mode monitor

echo "[+] Running interface test...(Enable Managed Mode)"
python3 wstt_interface.py mode managed

echo "[+] Tests complete! Log output:"
tail -n 20 $LOGFILE  # Show last 20 lines of logs
