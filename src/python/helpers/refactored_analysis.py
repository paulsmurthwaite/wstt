#!/usr/bin/env python3

"""
refactored_analysis.py

This file contains the refactored, single-pass analysis engine for WSTT.
It is designed to be more efficient and modular than the original implementation.

Author: Paul Smurthwaite
"""

from collections import defaultdict
import struct
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, EAPOL, Raw
from scapy.layers.dot11 import Dot11Deauth, Dot11Disas


def analyze_capture(packets):
    """
    Performs a single pass over the provided packets to build a comprehensive
    AnalysisContext object containing all fundamental evidence.

    :param packets: A list of Scapy packets from a capture file.
    :return: An AnalysisContext dictionary.
    """
    context = {
        "access_points": {},
        "eapol_frames": [],
        "deauth_frames": [],
        "data_traffic": [],
    }

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue

        # --- 1. AP Identification (Beacons & Probe Responses) ---
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = pkt.addr3
            if not bssid:
                continue

            # This logic is consolidated from the original get_known_aps
            ssid = "<hidden>"
            channel = None
            rsn_found = False
            country = None

            elt = pkt.getlayer(Dot11Elt)
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

            privacy = "privacy" in pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            # Update the AP dictionary, keeping the first-seen entry
            if bssid not in context["access_points"]:
                context["access_points"][bssid] = {
                    "bssid": bssid,
                    "ssid": ssid,
                    "channel": channel,
                    "privacy": privacy,
                    "rsn": rsn_found,
                    "country": country,
                    "vendor": bssid.upper()[0:8],
                    "interval": pkt[Dot11Beacon].beacon_interval if pkt.haslayer(Dot11Beacon) else None,
                    "first_seen": i
                }

        # --- 2. Deauthentication & Disassociation Frames ---
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            context["deauth_frames"].append({
                "frame_num": i,
                "sender": pkt.addr2,
                "receiver": pkt.addr1,
                "bssid": pkt.addr3,
                "reason_code": pkt.reason,
                "type": "deauth" if pkt.haslayer(Dot11Deauth) else "disassoc"
            })

        # --- 3. EAPOL Handshake Frames ---
        elif pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3:  # EAPOL-Key
            try:
                eapol_payload = pkt[EAPOL].load

                # Manually parse the key_info field to support older Scapy versions
                # that may not have the Dot11EAPOLKey class. The key_info field
                # is a 16-bit (2-byte) field starting at the second byte (offset 1).
                if len(eapol_payload) < 3:
                    continue
                key_info = struct.unpack('!H', eapol_payload[1:3])[0]

                pairwise = (key_info >> 3) & 1
                secure = (key_info >> 5) & 1
                install = (key_info >> 6) & 1
                ack = (key_info >> 7) & 1
                mic = (key_info >> 8) & 1

                msg_num = None
                if pairwise:
                    if ack and not mic: msg_num = 1
                    elif mic and not ack and not secure: msg_num = 2
                    elif ack and mic and install and secure: msg_num = 3
                    elif mic and not ack and secure: msg_num = 4

                if msg_num is None:
                    continue

                # Determine client/AP roles from DS bits
                to_ds = pkt.FCfield & 0x1
                from_ds = pkt.FCfield & 0x2
                if to_ds and not from_ds: client, ap = pkt.addr2, pkt.addr1
                elif not to_ds and from_ds: client, ap = pkt.addr1, pkt.addr2
                else: continue

                context["eapol_frames"].append({
                    "frame_num": i,
                    "client": client,
                    "ap": ap,
                    "msg_num": msg_num
                })

            except Exception:
                # Ignore frames that fail to parse
                continue

        # --- 4. Data Frames ---
        elif pkt.type == 2: # Data Frame
            to_ds = pkt.FCfield & 0x1
            from_ds = pkt.FCfield & 0x2

            if to_ds and not from_ds: # Client to AP
                direction = "c2a"
                client, ap = pkt.addr2, pkt.addr1
            elif not to_ds and from_ds: # AP to Client
                direction = "a2c"
                client, ap = pkt.addr1, pkt.addr2
            else:
                continue # Skip ad-hoc or WDS frames

            context["data_traffic"].append({
                "frame_num": i,
                "client": client,
                "ap": ap,
                "encrypted": bool(pkt.FCfield & 0x40),
                "direction": direction
            })

    return context


def detect_duplicate_handshakes(context):
    """
    Analyzes the pre-processed context to find evidence of Evil Twin attacks
    by correlating handshakes, deauthentications, and traffic flows.

    Returns a list of dictionaries, each representing a confirmed attack chain.
    """
    # Step 1: Group EAPOL messages by (client, ap) pair
    handshake_sessions = defaultdict(list)
    for frame in context['eapol_frames']:
        key = (frame['client'], frame['ap'])
        handshake_sessions[key].append(frame)

    # Step 2: Identify all complete 4-way handshakes
    complete_handshakes = []
    for (client, ap), frames in handshake_sessions.items():
        msg_nums = {f['msg_num'] for f in frames}
        if {1, 2, 3, 4}.issubset(msg_nums):
            # Find the start frame of this complete handshake
            first_frame = min((f for f in frames if f['msg_num'] == 1), key=lambda x: x['frame_num'])
            complete_handshakes.append({
                'client': client,
                'ap': ap,
                'start_frame': first_frame['frame_num']
            })

    # Step 3: Group complete handshakes by client
    client_activity = defaultdict(list)
    for hs in complete_handshakes:
        client_activity[hs['client']].append(hs)

    # Step 4: Find clients with multiple handshakes and check for attack pattern
    attack_chains = []
    for client, handshakes in client_activity.items():
        if len(handshakes) < 2:
            continue

        # Sort handshakes chronologically
        sorted_hs = sorted(handshakes, key=lambda x: x['start_frame'])

        # Check consecutive pairs of handshakes for the evil twin pattern
        for hs1, hs2 in zip(sorted_hs, sorted_hs[1:]):
            ap1, ap2 = hs1['ap'], hs2['ap']
            ssid1 = context['access_points'].get(ap1, {}).get('ssid')
            ssid2 = context['access_points'].get(ap2, {}).get('ssid')

            # Condition 1: APs must be different but have the same, non-hidden SSID
            if ap1 == ap2 or ssid1 is None or ssid1 == '<hidden>' or ssid1 != ssid2:
                continue

            # Condition 2: Check for a deauth frame between the two handshakes
            deauth_found = any(
                deauth['receiver'] == client and hs1['start_frame'] < deauth['frame_num'] < hs2['start_frame']
                for deauth in context['deauth_frames']
            )

            attack_chains.append({
                'client': client, 'ssid': ssid1, 'legit_ap': ap1, 'rogue_ap': ap2,
                'deauth_between': deauth_found, 'hs1_start': hs1['start_frame'], 'hs2_start': hs2['start_frame']
            })

    return attack_chains


def detect_rogue_aps(context):
    """
    Detects SSID collisions (multiple BSSIDs advertising the same SSID)
    by analyzing the pre-processed access_points context.
    """
    ssid_map = defaultdict(list)
    for bssid, data in context['access_points'].items():
        # Ignore hidden SSIDs as they can't be reliably compared
        if data["ssid"] and data["ssid"] != "<hidden>":
            ssid_map[data["ssid"]].append(bssid)

    rogue_entries = []
    for ssid, bssids in ssid_map.items():
        if len(bssids) > 1:
            rogue_entries.append({
                "ssid": ssid,
                "bssids": sorted(bssids),
                "count": len(bssids)
            })
    return rogue_entries


def detect_beacon_anomalies(context):
    """
    Detects beacon-level inconsistencies between APs advertising the same SSID
    by analyzing the pre-processed access_points context.
    """
    ssid_groups = defaultdict(list)
    for bssid, data in context['access_points'].items():
        ssid_groups[data['ssid']].append(data)

    anomalies = []
    for ssid, entries in ssid_groups.items():
        if len(entries) < 2 or ssid == "<hidden>":
            continue

        # Helper to check for inconsistencies in a specific property
        def check_inconsistency(prop_name, anomaly_type):
            prop_set = {e.get(prop_name) for e in entries if e.get(prop_name) is not None}
            if len(prop_set) > 1:
                anomalies.append({
                    "ssid": ssid,
                    "anomaly_type": anomaly_type,
                    "bssids": [e["bssid"] for e in entries]
                })

        check_inconsistency("rsn", "RSN mismatch")
        check_inconsistency("vendor", "Vendor OUI mismatch")
        check_inconsistency("interval", "Beacon Interval mismatch")
        check_inconsistency("country", "Country Code mismatch")

    return anomalies


def detect_client_traffic(context):
    """
    Detects bidirectional encrypted traffic between clients and APs
    by analyzing the pre-processed data_traffic context.
    """
    pair_counts = defaultdict(lambda: {"c2a": 0, "a2c": 0})
    for frame in context['data_traffic']:
        if not frame['encrypted']:
            continue
        key = (frame['client'], frame['ap'])
        # Use the pre-calculated direction from the context
        if frame.get('direction'):
            pair_counts[key][frame['direction']] += 1

    confirmed_pairs = []
    for (client, ap), counts in pair_counts.items():
        if counts["c2a"] > 0 and counts["a2c"] > 0:
            confirmed_pairs.append({
                "client": client,
                "ap": ap,
                "frames": counts["c2a"] + counts["a2c"]
            })
    return confirmed_pairs