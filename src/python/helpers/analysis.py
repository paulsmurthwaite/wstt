#!/usr/bin/env python3
"""analysis.py

Provides the core, single-pass analysis engine for the WSTT.

This module contains the primary `analyse_capture` function, which processes a
packet capture file once to build a comprehensive "context" object. This
context is then used by various modular detection functions to efficiently
identify evidence of specific wireless threats without re-parsing the file.

Author:      Paul Smurthwaite
Date:        2025-05-15
Module:      TM470-25B
"""

# ─── External Modules  ───
from collections import defaultdict, Counter
import struct
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq, Dot11Elt, EAPOL, Raw, ARP
from scapy.layers.dot11 import Dot11Deauth, Dot11Disas, Dot11Auth
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

def analyse_capture(packets):
    """
    Performs a single pass over packets to build a network analysis context.

    Args:
        packets (scapy.plist.PacketList): A list of Scapy packets from a capture file.

    Returns:
        dict: A comprehensive context dictionary containing structured data about
              access points, traffic, and key network events.
    """
    context = {
        "access_points": {},
        "beacon_frames": [],
        "auth_frames": [],
        "eapol_frames": [],
        "deauth_frames": [],
        "data_traffic": [],
        "arp_frames": [],
        "probe_requests": [],
        "probe_responses": [],
    }

    for i, pkt in enumerate(packets, start=1):
        if not pkt.haslayer(Dot11):
            continue

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            # Add to beacon_frames list for flood detection, which specifically
            # uses beacon frames, not probe responses.
            if pkt.haslayer(Dot11Beacon):
                context["beacon_frames"].append({
                    "time": pkt.time,
                    "bssid": pkt.addr3
                })

            if pkt.haslayer(Dot11ProbeResp):
				# In a probe response, addr1 is the client, addr3 is the BSSID
                client = pkt.addr1
                ap = pkt.addr3
                ssid = "<unknown>"
                elt = pkt.getlayer(Dot11Elt)
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 0 and elt.len > 0:
                        try: ssid = elt.info.decode(errors="ignore").strip()
                        except Exception: ssid = "<decode error>"
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                context["probe_responses"].append({
                    "time": pkt.time, "frame_num": i, "ap": ap, "client": client, "ssid": ssid
                })

            bssid = pkt.addr3
            if not bssid:
                continue

            ssid = "<hidden>"
            channel = None
            rsn_found = False
            wpa_found = False
            country = None

            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.len > 0:
                    try: ssid = elt.info.decode(errors="ignore").strip()
                    except Exception: ssid = "<decode error>"
                elif elt.ID == 3 and elt.len == 1: channel = elt.info[0]
                elif elt.ID == 48: rsn_found = True
                elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xf2\x01'):
                    wpa_found = True
                elif elt.ID == 7 and elt.len >= 2:
                    try: country = elt.info[:2].decode(errors="ignore")
                    except Exception: country = "<decode error>"
                elt = elt.payload.getlayer(Dot11Elt)

            privacy = "privacy" in pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            if bssid not in context["access_points"]:
                context["access_points"][bssid] = {
                    "bssid": bssid, "ssid": ssid, "channel": channel,
                    "privacy": privacy, "wpa": wpa_found, "rsn": rsn_found, "country": country,
                    "vendor": bssid.upper()[0:8],
                    "interval": pkt[Dot11Beacon].beacon_interval if pkt.haslayer(Dot11Beacon) else None,
                    "first_seen": i
                }

        elif pkt.haslayer(Dot11ProbeReq):
            client = pkt.addr2
            try:
                ssid = pkt.info.decode('utf-8', errors='ignore').strip()
            except Exception:
                ssid = "<decode error>"
            if not ssid:
                ssid = "<Broadcast>"
            context["probe_requests"].append({
                "time": pkt.time, "frame_num": i, "client": client, "ssid": ssid
            })
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            context["deauth_frames"].append({
                "time": pkt.time, "frame_num": i, "sender": pkt.addr2,
                "receiver": pkt.addr1, "bssid": pkt.addr3, "reason_code": pkt.reason,
                "type": "deauth" if pkt.haslayer(Dot11Deauth) else "disassoc"
            })

        elif pkt.haslayer(Dot11Auth):
            context["auth_frames"].append({
                "time": pkt.time,
                "frame_num": i,
                "sender": pkt.addr2,
                "receiver": pkt.addr1
            })

        elif pkt.haslayer(ARP):
            context["arp_frames"].append({
                "frame_num": i,
                "op": pkt[ARP].op, # 1=who-has, 2=is-at
                "hwsrc": pkt[ARP].hwsrc, # Sender MAC
                "psrc": pkt[ARP].psrc, # Sender IP
                "hwdst": pkt[ARP].hwdst, # Target MAC
                "pdst": pkt[ARP].pdst, # Target IP
            })

        elif pkt.haslayer(EAPOL) and pkt[EAPOL].type == 3:  # EAPOL-Key
            try:
                # To be robust against different Scapy versions, we check for the
                # 'key_info' attribute directly, rather than a specific layer class
                # that may not exist in all versions.
                if hasattr(pkt[EAPOL], 'key_info'):
                    # If the attribute exists, Scapy has fully dissected the frame.
                    key_info = pkt[EAPOL].key_info
                else:
                    # If not, get the raw payload of the EAPOL layer itself.
                    eapol_payload = bytes(pkt[EAPOL].payload)
                    if len(eapol_payload) < 3: continue
                    key_info = struct.unpack('!H', eapol_payload[1:3])[0]

                pairwise = (key_info >> 3) & 1
                ack = (key_info >> 7) & 1
                mic = (key_info >> 8) & 1
                secure = (key_info >> 5) & 1
                install = (key_info >> 6) & 1
                encrypted = (key_info >> 9) & 1

                msg_num = None
                if pairwise:
                    if ack and not mic: msg_num = 1
                    # Msg 2 is not encrypted, Msg 4 can be. This is the key differentiator.
                    elif mic and not ack and not secure and not encrypted: msg_num = 2
                    # More robust check for Msg 3, as the Secure flag is not always set.
                    elif ack and mic and install: msg_num = 3
                    # More robust check for Msg 4, as the Secure flag can be ambiguous.
                    elif mic and not ack and not install: msg_num = 4

                to_ds, from_ds = pkt.FCfield & 0x1, pkt.FCfield & 0x2
                if to_ds and not from_ds: client, ap = pkt.addr2, pkt.addr1
                elif not to_ds and from_ds: client, ap = pkt.addr1, pkt.addr2
                else: continue

                context["eapol_frames"].append({
                    "frame_num": i, "client": client, "ap": ap, "msg_num": msg_num
                })
            except Exception: continue

        elif pkt.type == 2: # Data Frame
            to_ds, from_ds = pkt.FCfield & 0x1, pkt.FCfield & 0x2

            if to_ds and not from_ds: # Client to AP
                direction, client, ap = "c2a", pkt.addr2, pkt.addr1
            elif not to_ds and from_ds: # AP to Client
                direction, client, ap = "a2c", pkt.addr1, pkt.addr2
            else:
                continue # Skip ad-hoc or WDS frames

            is_encrypted = bool(pkt.FCfield & 0x40)
            traffic_entry = {
                "frame_num": i, "client": client, "ap": ap,
                "encrypted": is_encrypted, "direction": direction
            }

            # If unencrypted, check for interesting layers
            if not is_encrypted:
                layers = [layer.__name__ for layer in [IP, TCP, UDP, ICMP, DNS, HTTPRequest, HTTPResponse] if pkt.haslayer(layer)]
                if layers:
                    traffic_entry['layers'] = layers

            context["data_traffic"].append(traffic_entry)

    return context


def detect_rogue_aps_context(context):
    """
    Detects SSID collisions from the analysis context.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing an SSID collision.
    """
    ssid_map = defaultdict(list)
    for bssid, data in context['access_points'].items():
        if data["ssid"] and data["ssid"] != "<hidden>":
            ssid_map[data["ssid"]].append(bssid)
    rogue_entries = []
    for ssid, bssids in ssid_map.items():
        if len(bssids) > 1:
            rogue_entries.append({"ssid": ssid, "bssids": sorted(bssids), "count": len(bssids)})
    return rogue_entries

def detect_beacon_anomalies_context(context):
    """
    Detects beacon inconsistencies between APs with the same SSID.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a detected anomaly.
    """
    ssid_groups = defaultdict(list)
    for bssid, data in context['access_points'].items():
        ssid_groups[data['ssid']].append(data)
    anomalies = []
    for ssid, entries in ssid_groups.items():
        if len(entries) < 2 or ssid == "<hidden>": continue
        def check_inconsistency(prop, type):
            prop_set = {e.get(prop) for e in entries if e.get(prop) is not None}
            if len(prop_set) > 1:
                anomalies.append({"ssid": ssid, "anomaly_type": type, "bssids": [e["bssid"] for e in entries]})
        check_inconsistency("rsn", "RSN mismatch")
        check_inconsistency("vendor", "Vendor OUI mismatch")
        check_inconsistency("interval", "Beacon Interval mismatch")
        check_inconsistency("country", "Country Code mismatch")
    return anomalies

def detect_duplicate_handshakes_context(context):
    """
    Identifies Evil Twin attack chains from the analysis context.

    This function analyzes EAPOL handshakes, deauthentication events, and
    traffic patterns to detect when a client is forced off a legitimate AP
    and re-associates with a rogue AP on the same SSID.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a confirmed attack chain.
    """
    handshake_sessions = defaultdict(list)
    for frame in context['eapol_frames']:
        handshake_sessions[(frame['client'], frame['ap'])].append(frame)

    complete_handshakes = []
    for (client, ap), frames in handshake_sessions.items():
        if {1, 2, 3, 4}.issubset({f['msg_num'] for f in frames}):
            first_frame = min((f for f in frames if f['msg_num'] == 1), key=lambda x: x['frame_num'])
            complete_handshakes.append({'client': client, 'ap': ap, 'start_frame': first_frame['frame_num']})

    client_activity = defaultdict(list)
    for hs in complete_handshakes:
        client_activity[hs['client']].append(hs)

    attack_chains = []

    # Get a map of SSIDs to BSSIDs to identify rogue/legit pairs
    ssid_map = defaultdict(list)
    for bssid, data in context['access_points'].items():
        if data["ssid"] and data["ssid"] != "<hidden>":
            ssid_map[data["ssid"]].append(bssid)

    for client, handshakes in client_activity.items():
        sorted_hs = sorted(handshakes, key=lambda x: x['start_frame'])

        # --- Logic 1: The "Perfect" Capture (two or more handshakes) ---
        if len(sorted_hs) >= 2:
            for hs1, hs2 in zip(sorted_hs, sorted_hs[1:]):
                ap1, ap2 = hs1['ap'], hs2['ap']
                ssid1 = context['access_points'].get(ap1, {}).get('ssid')
                ssid2 = context['access_points'].get(ap2, {}).get('ssid')
                if ap1 == ap2 or ssid1 is None or ssid1 == '<hidden>' or ssid1 != ssid2: continue
                deauth_found = any(
                    d['receiver'] == client and hs1['start_frame'] < d['frame_num'] < hs2['start_frame']
                    for d in context['deauth_frames']
                )
                attack_chains.append({
                    'client': client, 'ssid': ssid1, 'legit_ap': ap1, 'rogue_ap': ap2,
                    'deauth_between': deauth_found, 'hs1_start': hs1['start_frame'], 'hs2_start': hs2['start_frame']
                })

        # --- Logic 2: The "Realistic" Capture (one handshake with a rogue AP) ---
        elif len(sorted_hs) == 1:
            hs = sorted_hs[0]
            rogue_ap = hs['ap']
            ssid = context['access_points'].get(rogue_ap, {}).get('ssid')

            # Check if this handshake is with an AP involved in an SSID collision
            if not ssid or ssid == '<hidden>' or len(ssid_map.get(ssid, [])) < 2:
                continue

            # Find the legitimate AP (the other BSSID with the same SSID)
            legit_ap_candidates = [b for b in ssid_map[ssid] if b != rogue_ap]
            if not legit_ap_candidates: continue
            legit_ap = legit_ap_candidates[0] # Assume the first one is the legit one

            # Check for prior traffic with legit AP and a deauth before the new handshake
            prior_traffic_found = any(t['client'] == client and t['ap'] == legit_ap and t['frame_num'] < hs['start_frame'] for t in context['data_traffic'])
            deauth_found = any(d['receiver'] == client and d['frame_num'] < hs['start_frame'] for d in context['deauth_frames'])

            if prior_traffic_found and deauth_found:
                attack_chains.append({
                    'client': client, 'ssid': ssid, 'legit_ap': legit_ap, 'rogue_ap': rogue_ap,
                    'deauth_between': True, 'hs1_start': 'N/A (Inferred)', 'hs2_start': hs['start_frame']
                })

    return attack_chains

def detect_client_traffic_context(context):
    """
    Detects bidirectional encrypted traffic between a client and an AP.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a confirmed traffic pair.
    """
    pair_counts = defaultdict(lambda: {"c2a": 0, "a2c": 0})
    for frame in context['data_traffic']:
        if not frame['encrypted']: continue
        key = (frame['client'], frame['ap'])
        if frame.get('direction'):
            pair_counts[key][frame['direction']] += 1
    confirmed_pairs = []
    for (client, ap), counts in pair_counts.items():
        if counts["c2a"] > 0 and counts["a2c"] > 0:
            confirmed_pairs.append({"client": client, "ap": ap, "frames": counts["c2a"] + counts["a2c"]})
    return confirmed_pairs

def detect_unencrypted_traffic_context(context):
    """
    Detects bidirectional unencrypted traffic on open (non-WPA) networks.

    This function identifies clients communicating over unencrypted channels
    and lists the high-level protocols observed in the traffic.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a confirmed unencrypted flow.
    """
    pair_data = defaultdict(lambda: {"c2a": 0, "a2c": 0, "layers": set()})

    for frame in context['data_traffic']:
        if frame['encrypted']:
            continue
        key = (frame['client'], frame['ap'])
        if frame.get('direction'):
            pair_data[key][frame['direction']] += 1
        if frame.get('layers'):
            pair_data[key]['layers'].update(frame['layers'])

    confirmed_flows = []
    for (client, ap), data in pair_data.items():
        # A flow is only confirmed if it's bidirectional
        if data["c2a"] > 0 and data["a2c"] > 0:
            # And the AP is an open network (no privacy bit set)
            ap_properties = context['access_points'].get(ap, {})
            if not ap_properties.get('privacy'):
                confirmed_flows.append({
                    "client": client,
                    "ap": ap,
                    "frames": data["c2a"] + data["a2c"],
                    "layers": sorted(list(data['layers'])) or ["Unknown"]
                })
    return confirmed_flows

def detect_misconfigured_aps_context(context):
    """
    Detects misconfigured APs based on their advertised security protocols.

    This function iterates through all discovered access points and classifies
    their security posture based on a tiered risk model (Open, WEP, WPA1).

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a misconfigured AP
              and the reason for its classification.
    """
    misconfigured_aps = []
    for bssid, ap in context['access_points'].items():
        reason = None
        # Tier 1: Critical Misconfigurations
        if not ap.get('privacy'):
            reason = "Critical: Open Network"
        elif not ap.get('wpa') and not ap.get('rsn'):
            # If privacy is on but no WPA/RSN, it's WEP
            reason = "Critical: WEP (Legacy)"
        # Tier 2: Serious Misconfigurations
        elif ap.get('wpa') and not ap.get('rsn'):
            reason = "Serious: WPA1 (Legacy)"

        if reason:
            entry = ap.copy()
            entry['reason'] = reason
            misconfigured_aps.append(entry)

    return sorted(misconfigured_aps, key=lambda x: x.get('ssid', ''))

def detect_deauth_flood_context(context, threshold=20):
    """
    Detects deauthentication flood attacks from the analysis context.

    This function identifies flood events by counting deauthentication or
    disassociation frames sent to a specific target within one-second intervals
    and checking if the count exceeds a given threshold.

    Args:
        context (dict): The analysis context from `analyse_capture`.
        threshold (int): The minimum number of deauth/disassoc frames per
                         second to be considered a flood. Defaults to 20.

    Returns:
        list: A list of dictionaries, each representing a detected flood event.
    """
    time_buckets = defaultdict(int)

    for frame in context['deauth_frames']:
        # Use the packet's precise timestamp, truncated to the second
        timestamp = int(frame['time'])
        target = frame['receiver'] # The target of a deauth flood is the receiver

        key = (timestamp, target)
        time_buckets[key] += 1

    flood_events = []
    for (timestamp, target), count in time_buckets.items():
        if count >= threshold:
            flood_events.append({
                "timestamp": timestamp,
                "target": target,
                "frame_count": count,
                "threshold": threshold
            })

    return sorted(flood_events, key=lambda x: x['timestamp'])

def detect_directed_probe_response_context(context, time_window=2):
    """
    Detects directed probe responses, a key indicator of an AP impersonation attack.

    This function correlates Probe Requests from clients with subsequent Probe
    Responses from APs. It flags responses as suspicious if they are not from
    an AP that is actively broadcasting beacons.

    Args:
        context (dict): The analysis context from `analyse_capture`.
        time_window (int): The maximum time in seconds between a request and a
                           response to be considered correlated. Defaults to 2.

    Returns:
        list: A list of dictionaries, each representing a suspicious directed
              probe response event.
    """
    suspicious_responses = []
    reported_events = set()

    # Create a quick lookup for beaconing APs (those with a beacon interval)
    beaconing_aps = {bssid for bssid, data in context['access_points'].items() if data.get('interval') is not None}

    # Sort both lists by time to allow for efficient correlation
    sorted_requests = sorted(context.get('probe_requests', []), key=lambda x: x['time'])
    sorted_responses = sorted(context.get('probe_responses', []), key=lambda x: x['time'])

    req_idx = 0
    for resp in sorted_responses:
        # Find the window of relevant requests
        while req_idx < len(sorted_requests) and sorted_requests[req_idx]['time'] < resp['time'] - time_window:
            req_idx += 1

        # Search for a matching request in the current window
        for i in range(req_idx, len(sorted_requests)):
            req = sorted_requests[i]
            if req['time'] > resp['time']: break

            if req['client'] == resp['client'] and req['ssid'] == resp['ssid'] and req['ssid'] != "<Broadcast>":
                # A non-beaconing AP sending a directed response is highly suspicious.
                if resp['ap'] not in beaconing_aps:
                    event_key = (resp['client'], resp['ssid'], resp['ap'])
                    if event_key not in reported_events:
                        suspicious_responses.append({
                            "client": resp['client'], "ssid": resp['ssid'], "rogue_ap": resp['ap'],
                            "confidence": "High (Non-Beaconing AP)", "req_frame": req['frame_num'], "resp_frame": resp['frame_num']
                        })
                        reported_events.add(event_key)
                        break
    return suspicious_responses

def detect_arp_spoofing_context(context):
    """
    Detects ARP spoofing attacks by identifying IP-MAC address contradictions.

    This function builds a "ground truth" map of IP to MAC addresses from
    the first ARP reply seen for each IP. It then flags any subsequent ARP
    reply where the same IP is claimed by a different MAC address.

    Args:
        context (dict): The analysis context from `analyse_capture`.

    Returns:
        list: A list of dictionaries, each representing a detected spoofing event.
    """
    ip_mac_map = {}
    spoofing_events = []
    reported_spoofs = set()

    # Sort frames by frame number to process in order
    sorted_arp_frames = sorted(context.get('arp_frames', []), key=lambda x: x['frame_num'])

    for frame in sorted_arp_frames:
        # We are interested in ARP replies ("is-at")
        if frame['op'] != 2:
            continue

        ip = frame['psrc']
        mac = frame['hwsrc']

        if ip in ip_mac_map:
            legit_mac = ip_mac_map[ip]
            if mac != legit_mac:
                # This is a contradiction, potential spoofing
                spoof_key = (ip, legit_mac, mac)
                if spoof_key not in reported_spoofs:
                    spoofing_events.append({"ip_address": ip, "legit_mac": legit_mac, "rogue_mac": mac, "first_frame": frame['frame_num']})
                    reported_spoofs.add(spoof_key)
        else:
            # First time we see this IP, establish it as ground truth
            ip_mac_map[ip] = mac

    return spoofing_events

def detect_auth_flood_context(context, threshold=20):
    """
    Detects authentication flood attacks from the analysis context.

    This function identifies flood events by counting authentication frames
    sent to a specific target AP within one-second intervals and checking if
    the count exceeds a given threshold.

    Args:
        context (dict): The analysis context from `analyse_capture`.
        threshold (int): The minimum number of auth frames per second to be
                         considered a flood. Defaults to 20.

    Returns:
        list: A list of dictionaries, each representing a detected flood event.
    """
    time_buckets = defaultdict(int)

    for frame in context['auth_frames']:
        timestamp = int(frame['time'])
        # The target of an auth flood is the receiver (the AP)
        target = frame['receiver']

        key = (timestamp, target)
        time_buckets[key] += 1

    flood_events = []
    for (timestamp, target), count in time_buckets.items():
        if count >= threshold:
            flood_events.append({
                "timestamp": timestamp,
                "target_ap": target,
                "frame_count": count
            })

    return sorted(flood_events, key=lambda x: x['timestamp'])

def detect_beacon_flood_context(context, volume_threshold=100, variety_threshold=20):
    """
    Detects beacon flood attacks from the analysis context.

    This function identifies flood events by analysing two metrics within
    one-second intervals:
    1. The total volume of beacon frames.
    2. The variety of unique source BSSIDs.

    Args:
        context (dict): The analysis context from `analyse_capture`.
        volume_threshold (int): The minimum number of beacons per second to be
                                considered a flood. Defaults to 100.
        variety_threshold (int): The minimum number of unique BSSIDs per second
                                 to be considered a flood. Defaults to 20.

    Returns:
        list: A list of dictionaries, each representing a detected flood event.
    """
    time_buckets = defaultdict(list)

    for frame in context['beacon_frames']:
        timestamp = int(frame['time'])
        bssid = frame['bssid']
        time_buckets[timestamp].append(bssid)

    flood_events = []
    for timestamp, bssids in time_buckets.items():
        total_beacons = len(bssids)
        unique_bssids = len(set(bssids))

        if total_beacons >= volume_threshold or unique_bssids >= variety_threshold:
            flood_events.append({
                "timestamp": timestamp, "total_beacons": total_beacons,
                "unique_bssids": unique_bssids,
            })

    return sorted(flood_events, key=lambda x: x['timestamp'])
