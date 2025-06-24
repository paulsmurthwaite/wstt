#!/usr/bin/env python3

from collections import defaultdict
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, EAPOL, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.dot11 import Dot11Deauth, Dot11Disas

def get_known_aps(packets):
    """
    Extracts all access points observed in the capture file.
    Returns a dictionary mapping BSSID → AP metadata dict.
    """

    known_aps = {}

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            continue

        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            continue

        # Parse SSID and metadata
        ssid = "<hidden>"
        rsn_found = False
        channel = None
        beacon_interval = None
        country = None

        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0 and elt.len > 0:
                try:
                    ssid = elt.info.decode(errors="ignore").strip()
                except Exception:
                    ssid = "<decode error>"
            elif elt.ID == 3 and elt.len == 1:
                channel = elt.info[0]
            elif elt.ID == 48:
                rsn_found = True
            elif elt.ID == 7 and elt.len >= 2:
                try:
                    country = elt.info[:2].decode(errors="ignore")
                except Exception:
                    country = "<decode error>"
            elt = elt.payload.getlayer(Dot11Elt)

        # Beacon interval: pulled from Dot11Beacon layer if available
        beacon_interval = (
            pkt[Dot11Beacon].beacon_interval
            if pkt.haslayer(Dot11Beacon) else None
        )

        known_aps[bssid] = {
            "ssid": ssid,
            "rsn": rsn_found,
            "channel": channel,
            "interval": beacon_interval,
            "country": country,
            "first_seen": i
        }

    return known_aps

# ─────────────────────────────────────────────────────────────
# Check if a MAC address belongs to a known access point
# ─────────────────────────────────────────────────────────────
def is_access_point(mac, known_aps):
    """
    Returns True if the MAC address appears in the known_aps dictionary.
    """
    return mac in known_aps

# ─────────────────────────────────────────────────────────────
# Check if a MAC address appears to be a client device
# ─────────────────────────────────────────────────────────────
def is_client(mac, known_aps):
    """
    Returns True if the MAC address does NOT appear in the known_aps dictionary.
    """
    return mac not in known_aps

def parse_ap_frames(packets):
    access_points = []
    seen_bssids = set()

    for pkt in packets:
        try:
            if not pkt.haslayer(Dot11):
                continue

            if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
                continue

            dot11 = pkt[Dot11]
            bssid = dot11.addr3 or "<unknown>"

            if not bssid or bssid in seen_bssids:
                continue
            seen_bssids.add(bssid)

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
                elif elt.ID == 48:
                    rsn_found = True
                elt = elt.payload.getlayer(Dot11Elt)

            privacy = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").find("privacy") != -1 or \
                      pkt.sprintf("{Dot11ProbeResp:%Dot11ProbeResp.cap%}").find("privacy") != -1

            ap = {
                "ssid": ssid,
                "bssid": bssid,
                "privacy": privacy,
                "rsn": rsn_found
            }
            access_points.append(ap)

        except Exception:
            continue

    return access_points

def find_client_associations(packets, open_aps):
    open_bssids = {ap["bssid"] for ap in open_aps if not ap["privacy"] and not ap["rsn"]}
    pair_counts = {}
    confirmed_pairs = []

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        if dot11.type != 2:
            continue

        src = dot11.addr2
        dst = dot11.addr1

        if not src or not dst:
            continue

        if src in open_bssids and dst != src:
            key = (dst, src)
            pair_counts.setdefault(key, {"c2a": 0, "a2c": 0})
            pair_counts[key]["a2c"] += 1
        elif dst in open_bssids and src != dst:
            key = (src, dst)
            pair_counts.setdefault(key, {"c2a": 0, "a2c": 0})
            pair_counts[key]["c2a"] += 1

    for (client, ap), counts in pair_counts.items():
        if counts["c2a"] > 0 and counts["a2c"] > 0:
            confirmed_pairs.append({
                "client": client,
                "ap": ap,
                "frames": counts["c2a"] + counts["a2c"]
            })

    return confirmed_pairs

def inspect_unencrypted_frames(packets):
    PROTOCOL_LAYERS = [IP, TCP, UDP, ICMP, DNS, HTTPRequest, HTTPResponse]
    summary = {}
    total_frames = 0

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        if dot11.type != 2:
            continue

        fc_protected = bool(dot11.FCfield & 0x40)
        if fc_protected:
            continue

        src = dot11.addr2
        dst = dot11.addr1
        if not src or not dst:
            continue

        pair = tuple(sorted([src, dst]))
        if pair not in summary:
            summary[pair] = {"count": 0, "layers": set()}

        summary[pair]["count"] += 1
        total_frames += 1

        for layer in PROTOCOL_LAYERS:
            if pkt.haslayer(layer):
                summary[pair]["layers"].add(layer.__name__)

    results = []
    for (mac1, mac2), data in summary.items():
        results.append({
            "client": mac1,
            "ap": mac2,
            "frames": data["count"],
            "layers": sorted(data["layers"]) or ["None"]
        })

    return results

def detect_rogue_aps(packets):
    """
    Detects impersonation of a known SSID by:
    - Multiple BSSIDs advertising the same SSID (SSID collision)
    - A single BSSID reused with differing fingerprints (BSSID spoofing)
    Returns a list of suspicious SSID records.
    Used by T004
    """

    ssid_bssid_map = {}           # SSID -> set(BSSIDs)
    ssid_bssid_fingerprints = {}  # SSID -> BSSID -> list of fingerprints

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            continue

        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            continue

        # Extract SSID and fingerprint info
        ssid = "<hidden>"
        rsn_found = False
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0 and elt.len > 0:
                try:
                    ssid = elt.info.decode(errors="ignore").strip()
                except Exception:
                    ssid = "<decode error>"
            elif elt.ID == 48:
                rsn_found = True
            elt = elt.payload.getlayer(Dot11Elt)

        vendor = bssid.upper()[0:8]  # MAC OUI

        fingerprint = {
            "rsn": rsn_found,
            "vendor": vendor,
            "first_seen": i
        }

        # Record BSSID per SSID
        ssid_bssid_map.setdefault(ssid, set()).add(bssid)
        ssid_bssid_fingerprints.setdefault(ssid, {}).setdefault(bssid, []).append(fingerprint)

    rogue_entries = []

    for ssid, bssids in ssid_bssid_map.items():
        if len(bssids) > 1:
            rogue_entries.append({
                "ssid": ssid,
                "bssids": sorted(bssids),
                "count": len(bssids)
            })
        else:
            bssid = next(iter(bssids))
            fingerprints = ssid_bssid_fingerprints[ssid][bssid]

            # Check for inconsistent fingerprint values for the same BSSID
            rsn_set = {fp["rsn"] for fp in fingerprints}
            vendor_set = {fp["vendor"] for fp in fingerprints}

            if len(rsn_set) > 1 or len(vendor_set) > 1:
                rogue_entries.append({
                    "ssid": ssid,
                    "bssids": [bssid],
                    "count": 1
                })

    return rogue_entries

def detect_duplicate_handshakes(packets, known_aps):
    """
    Detects:
    1. Full WPA2 4-way handshakes (EAPOL types 1–4)
    2. Repeated EAPOL type 3 messages separated by deauth/disassoc
    3. Deauth events without any observed handshake
    Returns a list of per-client evidence blocks.
    Used by T004.
    """
    handshake_tracker = {}
    frame_start_map = {}
    full_sequences = defaultdict(list)
    partial_type3 = defaultdict(list)
    deauth_events = []

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]
        src = dot11.addr2
        dst = dot11.addr1

        if not src or not dst:
            continue

        # Capture deauth/disassociation events
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            deauth_events.append((i, src, dst))
            continue

        # Handle EAPOL handshake frames
        if pkt.haslayer(EAPOL):
            eapol_type = pkt[EAPOL].type

            # Use known_aps to determine AP and client roles
            if is_access_point(src, known_aps):
                ap, client = src, dst
            elif is_access_point(dst, known_aps):
                ap, client = dst, src
            else:
                continue  # Cannot determine roles reliably

            key = (client, ap)

            if eapol_type == 3:
                partial_type3[key].append(i)

            if key not in handshake_tracker:
                handshake_tracker[key] = set()
                frame_start_map[key] = i

            handshake_tracker[key].add(eapol_type)

            if len(handshake_tracker[key]) == 4:
                full_sequences[key].append(frame_start_map[key])
                del handshake_tracker[key]
                del frame_start_map[key]

    # Final output
    duplicates = []
    seen_keys = set(full_sequences.keys()) | set(partial_type3.keys())

    for key in seen_keys:
        client, ap = key
        full_frames = full_sequences.get(key, [])
        partial_frames = partial_type3.get(key, [])
        all_frames = sorted(partial_frames + full_frames)

        deauths = [
            idx for idx, s, d in deauth_events
            if (s == ap and d == client) and any(
                f1 < idx < f2 for f1, f2 in zip(all_frames, all_frames[1:])
            )
        ]

        duplicates.append({
            "client": client,
            "ap": ap,
            "handshakes": full_frames if full_frames else None,
            "partial_type3_only": partial_frames if partial_frames and not full_frames else None,
            "deauths_between": deauths if deauths else None,
            "status": (
                "complete_match" if full_frames else
                "partial_match" if partial_frames else
                "deauth_only"
            )
        })

    return duplicates

def detect_beacon_anomalies(packets):
    """
    Detects beacon-level inconsistencies between APs advertising the same SSID.
    Flags mismatches in RSN, vendor OUI, beacon interval, and country code.
    Returns a list of anomaly reports.
    Used by T004
    """

    ssid_info = {}

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue
        if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
            continue

        dot11 = pkt[Dot11]
        bssid = dot11.addr3
        if not bssid:
            continue

        ssid = "<hidden>"
        rsn_found = False
        country_code = None

        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 0 and elt.len > 0:
                try:
                    ssid = elt.info.decode(errors="ignore").strip()
                except Exception:
                    ssid = "<decode error>"
            elif elt.ID == 7:  # Country Information
                try:
                    country_code = elt.info[:2].decode(errors="ignore")
                except Exception:
                    country_code = "<decode error>"
            elif elt.ID == 48:
                rsn_found = True
            elt = elt.payload.getlayer(Dot11Elt)

        vendor_prefix = bssid.upper()[0:8]
        beacon_interval = pkt[Dot11Beacon].beacon_interval if pkt.haslayer(Dot11Beacon) else None

        ssid_info.setdefault(ssid, []).append({
            "bssid": bssid,
            "rsn": rsn_found,
            "vendor": vendor_prefix,
            "interval": beacon_interval,
            "country": country_code
        })

    anomalies = []

    for ssid, entries in ssid_info.items():
        if len(entries) < 2:
            continue

        # RSN inconsistency
        rsn_set = {e["rsn"] for e in entries}
        if len(rsn_set) > 1:
            anomalies.append({
                "ssid": ssid,
                "anomaly_type": "RSN mismatch",
                "bssids": [e["bssid"] for e in entries]
            })

        # Vendor inconsistency
        vendor_set = {e["vendor"] for e in entries}
        if len(vendor_set) > 1:
            anomalies.append({
                "ssid": ssid,
                "anomaly_type": "Vendor OUI mismatch",
                "bssids": [e["bssid"] for e in entries]
            })

        # Beacon Interval inconsistency
        interval_set = {e["interval"] for e in entries if e["interval"] is not None}
        if len(interval_set) > 1:
            anomalies.append({
                "ssid": ssid,
                "anomaly_type": "Beacon Interval mismatch",
                "bssids": [e["bssid"] for e in entries]
            })

        # Country Code inconsistency
        country_set = {e["country"] for e in entries if e["country"] is not None}
        if len(country_set) > 1:
            anomalies.append({
                "ssid": ssid,
                "anomaly_type": "Country Code mismatch",
                "bssids": [e["bssid"] for e in entries]
            })

    return anomalies

def detect_client_traffic(packets, known_aps):
    """
    Detects bidirectional encrypted traffic between clients and APs.
    Returns a list of client/AP pairs with frame counts.
    Used by T004
    """

    pair_counts = {}
    confirmed_pairs = []

    for pkt in packets:
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]

        # We're only interested in data frames (type 2)
        if dot11.type != 2:
            continue

        # Must be encrypted (FCfield bit 0x40 = Protected Frame)
        if not (dot11.FCfield & 0x40):
            continue

        src = dot11.addr2
        dst = dot11.addr1

        if not src or not dst:
            continue

        # Determine who is client and who is AP using known_aps
        if is_access_point(src, known_aps):
            ap, client = src, dst
        elif is_access_point(dst, known_aps):
            ap, client = dst, src
        else:
            continue  # Skip if roles cannot be resolved

        key = (client, ap)
        pair_counts.setdefault(key, {"c2a": 0, "a2c": 0})

        if src == client:
            pair_counts[key]["c2a"] += 1
        elif src == ap:
            pair_counts[key]["a2c"] += 1

    for (client, ap), counts in pair_counts.items():
        if counts["c2a"] > 0 and counts["a2c"] > 0:
            confirmed_pairs.append({
                "client": client,
                "ap": ap,
                "frames": counts["c2a"] + counts["a2c"]
            })

    return confirmed_pairs

def detect_client_disassociation(packets, known_aps):
    """
    Detects disassociation or deauthentication frames sent by clients to APs.
    Returns a list of disconnection events with frame metadata.
    Used by T004
    """
    from scapy.all import Dot11

    disconnections = []

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue

        dot11 = pkt[Dot11]

        if dot11.type != 0:  # Management frame
            continue

        # Subtype 10 = Disassociation, 12 = Deauthentication
        if dot11.subtype in [10, 12]:
            src = dot11.addr2
            dst = dot11.addr1

            if not src or not dst:
                continue

            # Determine AP and client roles
            if is_access_point(src, known_aps):
                ap, client = src, dst
            elif is_access_point(dst, known_aps):
                ap, client = dst, src
            else:
                continue  # Skip if roles can't be determined

            disconnections.append({
                "client": client,
                "ap": ap,
                "frame_type": "disassoc" if dot11.subtype == 10 else "deauth",
                "frame_number": i
            })

    return disconnections