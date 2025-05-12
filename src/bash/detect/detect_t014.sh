#!/bin/bash

# T014 – ARP Spoofing Detection
# Detects multiple MACs claiming the same IP address

# Usage: ./detect_t014.sh
# Requires: .pcap capture file, tshark

# Environment
source "$(dirname "${BASH_SOURCE[0]}")/../load_env.sh"

# Header
echo ""
echo "[ T014 – ARP Spoofing Detection ]"

# Select detection mode
echo ""
echo "[+] Select detection mode:"
echo "    [1] Basic"
echo "    [2] Advanced"
read -rp "    → " DETECT_MODE

if [[ "$DETECT_MODE" != "1" && "$DETECT_MODE" != "2" ]]; then
    echo "[ERROR] Invalid selection. Choose 1 or 2."
    exit 1
fi

# Select capture file
PCAP_FILE=$(select_pcap_file) || exit 1
validate_pcap_file "$PCAP_FILE" || exit 1

# Basic detection
if [ "$DETECT_MODE" = "1" ]; then
    echo ""
    echo "[INFO] Running basic detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    echo "[RESULT] Duplicate IP-to-MAC relationships (possible ARP spoofing):"
    echo "--------------------------------------------------"

    # Run detection
    tshark -r "$PCAP_FILE" \
        -Y "arp.opcode == 2" \
        -T fields -e arp.src.proto_ipv4 -e eth.src 2>/dev/null |
    awk '
    {
        ip = $1
        mac = $2
        if (ip != "" && mac != "") {
            key = ip "|" mac
            if (!(key in combo)) {
                combo[key] = 1
                ip_mac_map[ip] = ip_mac_map[ip] "|" mac
                count[ip]++
            }
        }
    }
    END {
        for (ip in count) {
            if (count[ip] > 1) {
                print "  IP: " ip
                split(ip_mac_map[ip], macs, "|")
                for (i in macs) {
                    if (macs[i] != "") {
                        print "     → " macs[i]
                    }
                }
                print ""
            }
        }
    }'

    echo "--------------------------------------------------"
    echo ""

# Advanced detection
elif [ "$DETECT_MODE" = "2" ]; then
    echo ""
    echo "[INFO] Running advanced detection on:"
    echo "    → $(basename "$PCAP_FILE")"
    echo ""

    # Run detection: python3 ./analysis/detect_t014.py "$PCAP_FILE"
    echo "[WARNING] Advanced detection not yet implemented."
    exit 1
fi