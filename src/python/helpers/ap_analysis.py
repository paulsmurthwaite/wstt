#!/usr/bin/env python3

from helpers.output import *
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt

def parse_ap_frames(packets):
    """
    Parses 802.11 Beacon and Probe Response frames from a Scapy packet list
    to identify Access Points.

    Args:
        packets: List of Scapy packets.

    Returns:
        List of dicts containing: ssid, bssid, privacy, rsn
    """
    access_points = []
    seen_bssids = set()

    for index, pkt in enumerate(packets, start=1):
        try:
            if not pkt.haslayer(Dot11):
                continue

            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                continue

            dot11 = pkt[Dot11]
            bssid = dot11.addr3 or "<unknown>"

            # Skip broadcast/malformed BSSIDs
            if not bssid or bssid in seen_bssids:
                continue
            seen_bssids.add(bssid)

            # Extract SSID from Dot11Elt (tag 0)
            ssid = "<hidden>"
            rsn_found = False
            privacy = False

            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.len > 0:
                    try:
                        ssid = elt.info.decode(errors="ignore").strip()
                    except Exception:
                        ssid = "<decode error>"
                elif elt.ID == 48:  # RSN tag
                    rsn_found = True
                elt = elt.payload.getlayer(Dot11Elt)

            # Determine privacy from capability flags
            privacy = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").find("privacy") != -1 \
                      or pkt.sprintf("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").find("privacy") != -1

            # Trace log
            print_info(f"Frame {index}: SSID='{ssid}' BSSID={bssid} Privacy={privacy} RSN={rsn_found}")

            # Add to result
            ap = {
                "ssid": ssid,
                "bssid": bssid,
                "privacy": privacy,
                "rsn": rsn_found
            }
            access_points.append(ap)

        except Exception as e:
            print_error(f"[x] AP frame parse failed: {e}")
            continue

    return access_points