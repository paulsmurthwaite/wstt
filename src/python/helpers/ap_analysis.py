#!/usr/bin/env python3

from helpers.output import *
from scapy.all import RadioTap, Dot11Elt

def extract_ssid_from_raw(pkt):
    """
    Attempts to extract the SSID from a raw 802.11 management frame using Scapy.

    Args:
        pkt: PyShark packet object with raw bytes enabled.

    Returns:
        SSID string or '<hidden>' if extraction fails.
    """
    try:
        raw = bytes(pkt.get_raw_packet())
        scapy_pkt = RadioTap(raw)

        # Walk through all Dot11Elt layers to find Tag 0 (SSID)
        ssid = "<hidden>"
        elt = scapy_pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID tag
                if elt.len > 0:
                    ssid = elt.info.decode(errors="ignore").strip()
                break
            elt = elt.payload.getlayer(Dot11Elt)
        return ssid
    except Exception as e:
        print_warning(f"[debug] Scapy SSID extraction failed: {e}")
        return "<hidden>"

def parse_ap_frames(capture):
    """
    Parse beacon and probe response frames from a PCAP capture to identify access points.

    Returns:
        List of dictionaries with keys: ssid, bssid, privacy, rsn
    """
    access_points = []
    seen_bssids = set()

    for pkt in capture:
        try:
            subtype_str = pkt.wlan.get_field("fc.type_subtype")
            if subtype_str is None:
                continue  # Skip if missing
            subtype = int(subtype_str, 16)

            ssid = extract_ssid_from_raw(pkt)

            bssid = getattr(pkt.wlan, "bssid", None)
            privacy = getattr(pkt.wlan, "fixed_capabilities_privacy", "0") == "1"
            rsn = hasattr(pkt.wlan, "rsn")

            # Deduplicate by BSSID
            if not bssid or bssid in seen_bssids:
                continue
            seen_bssids.add(bssid)

            # Debug trace – only for first appearance
            print_info(f"[trace] Parsed frame: SSID='{ssid}' BSSID={bssid} Privacy={privacy} RSN={rsn}")

            # Add to result list
            ap = {
                "ssid": ssid,
                "bssid": bssid,
                "privacy": privacy,
                "rsn": rsn
            }
            access_points.append(ap)

        except Exception as e:
            print_error(f"AP frame parse failed: {str(e)}")
            continue

    return access_points
