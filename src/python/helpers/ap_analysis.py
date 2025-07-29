#!/usr/bin/env python3

from collections import defaultdict
import struct
from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, EAPOL, Raw
from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS

# ─────────────────────────────────────────────────────────────
# Single-Pass Analysis Engine (Scapy-based)
# ─────────────────────────────────────────────────────────────

def analyse_capture(packets):
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

            ssid = "<hidden>"
            channel = None
            rsn_found = False
            country = None

            elt = pkt.getlayer(Dot11Elt)
            while isinstance(elt, Dot11Elt):
                if elt.ID == 0 and elt.len > 0:
                    try: ssid = elt.info.decode(errors="ignore").strip()
                    except Exception: ssid = "<decode error>"
                elif elt.ID == 3 and elt.len == 1: channel = elt.info[0]
                elif elt.ID == 48: rsn_found = True
                elif elt.ID == 7 and elt.len >= 2:
                    try: country = elt.info[:2].decode(errors="ignore")
                    except Exception: country = "<decode error>"
                elt = elt.payload.getlayer(Dot11Elt)

            privacy = "privacy" in pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}{Dot11ProbeResp:%Dot11ProbeResp.cap%}")

            if bssid not in context["access_points"]:
                context["access_points"][bssid] = {
                    "bssid": bssid, "ssid": ssid, "channel": channel,
                    "privacy": privacy, "rsn": rsn_found, "country": country,
                    "vendor": bssid.upper()[0:8],
                    "interval": pkt[Dot11Beacon].beacon_interval if pkt.haslayer(Dot11Beacon) else None,
                    "first_seen": i
                }

        # --- 2. Deauthentication & Disassociation Frames ---
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            context["deauth_frames"].append({
                "time": pkt.time, "frame_num": i, "sender": pkt.addr2,
                "receiver": pkt.addr1, "bssid": pkt.addr3, "reason_code": pkt.reason,
                "type": "deauth" if pkt.haslayer(Dot11Deauth) else "disassoc"
            })

        # --- 3. EAPOL Handshake Frames ---
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

        # --- 4. Data Frames ---
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
    Detects SSID collisions (multiple BSSIDs advertising the same SSID)
    by analysing the pre-processed access_points context.
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
    Detects beacon-level inconsistencies between APs advertising the same SSID
    by analysing the pre-processed access_points context.
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
    Analyses the pre-processed context to find evidence of Evil Twin attacks,
    supporting both "perfect" and "realistic" capture scenarios.

    :param context: The AnalysisContext object from analyse_capture.
    :return: A list of dictionaries, each representing a confirmed attack chain.
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
    Detects bidirectional encrypted traffic between clients and APs
    by analysing the pre-processed data_traffic context.
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
    Detects bidirectional unencrypted traffic on open networks and identifies the protocols.
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

def detect_deauth_flood_context(context, threshold=20):
    """
    Detects deauthentication floods by counting deauth/disassoc frames sent to
    a specific target within one-second intervals.
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
