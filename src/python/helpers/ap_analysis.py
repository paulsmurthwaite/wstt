from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

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