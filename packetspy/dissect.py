import time

# --- TCP flag expansion ---

_FLAG_SHORT_TO_LONG = {
    "S": "SYN",
    "A": "ACK",
    "F": "FIN",
    "R": "RST",
    "P": "PSH",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

_FLAG_CONTEXT = {
    frozenset(["SYN"]): "Connection request (handshake step 1)",
    frozenset(["SYN", "ACK"]): "Connection accepted (handshake step 2)",
    frozenset(["ACK"]): "Acknowledgement",
    frozenset(["PSH", "ACK"]): "Delivering data",
    frozenset(["FIN", "ACK"]): "Closing connection",
    frozenset(["RST"]): "Connection forcibly reset",
    frozenset(["RST", "ACK"]): "Connection forcibly reset",
}


def _expand_flags(scapy_flags):
    """Convert Scapy FlagValue (e.g. 'PA') to expanded string (e.g. 'PSH ACK')."""
    raw = str(scapy_flags)
    expanded = [_FLAG_SHORT_TO_LONG.get(ch, ch) for ch in raw]
    return " ".join(expanded)


def _flag_context_description(expanded_flags_str):
    """Return a human-readable description for a set of expanded flag names."""
    flag_set = frozenset(expanded_flags_str.split())
    return _FLAG_CONTEXT.get(flag_set, "")


def dissect_packet(pkt, seq_num):
    """Parse a Scapy packet into a display-friendly dict."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether

    result = {
        "num": seq_num,
        "timestamp": time.time(),
        "length": len(pkt),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "info": "",
        "process": None,
        "pid": None,
    }

    if pkt.haslayer(Ether):
        result["src_mac"] = pkt[Ether].src
        result["dst_mac"] = pkt[Ether].dst

    if pkt.haslayer(IP):
        result["src_ip"] = pkt[IP].src
        result["dst_ip"] = pkt[IP].dst
        result["protocol"] = "IP"

        if pkt.haslayer(TCP):
            result["protocol"] = "TCP"
            result["src_port"] = pkt[TCP].sport
            result["dst_port"] = pkt[TCP].dport
            raw_flags = str(pkt[TCP].flags)
            expanded = _expand_flags(pkt[TCP].flags)
            result["flags_raw"] = raw_flags
            result["info"] = f"TCP {pkt[TCP].sport} \u2192 {pkt[TCP].dport} [{expanded}]"
        elif pkt.haslayer(UDP):
            result["protocol"] = "UDP"
            result["src_port"] = pkt[UDP].sport
            result["dst_port"] = pkt[UDP].dport
            payload_len = len(pkt[UDP].payload)
            result["info"] = f"UDP {pkt[UDP].sport} \u2192 {pkt[UDP].dport} len={payload_len}"
        else:
            result["info"] = f"IP {pkt[IP].src} \u2192 {pkt[IP].dst} proto={pkt[IP].proto}"
    else:
        result["info"] = pkt.summary()

    return result


def dissect_packet_detail(raw_pkt, parsed_pkt, profile=None, local_ip=None):
    """Return full packet detail: all layers, hex dump, direction."""
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    result = {
        "num": parsed_pkt.get("num"),
        "timestamp": parsed_pkt.get("timestamp"),
        "length": parsed_pkt.get("length"),
        "process": parsed_pkt.get("process"),
        "pid": parsed_pkt.get("pid"),
        "direction": _get_direction(raw_pkt, profile, local_ip),
        "layers": [],
        "payload": None,
        "addons": [],
    }

    # Walk the layer chain
    layer = raw_pkt
    while layer:
        layer_name = layer.__class__.__name__
        if layer_name == "Raw":
            # Raw payload goes to the payload section
            payload_bytes = bytes(layer.load)
            result["payload"] = {
                "length": len(payload_bytes),
                "hexdump": _format_hexdump(payload_bytes),
            }
            break
        if layer_name == "Padding":
            break

        fields = []
        for fd in layer.fields_desc:
            try:
                val = getattr(layer, fd.name, None)
                if val is None:
                    continue
                # Convert to JSON-safe types
                if isinstance(val, bytes):
                    val = val.hex()
                elif isinstance(val, (int, float, str, bool)):
                    pass
                else:
                    val = str(val)
                fields.append({"name": fd.name, "value": val})
            except Exception:
                continue

        # Add expanded flag description for TCP layer
        if layer_name == "TCP":
            try:
                expanded = _expand_flags(layer.flags)
                ctx = _flag_context_description(expanded)
                desc = f"{expanded} \u2014 {ctx}" if ctx else expanded
                fields.append({"name": "flags_description", "value": desc})
            except Exception:
                pass

        result["layers"].append({"name": layer_name, "fields": fields})
        layer = layer.payload if layer.payload and not isinstance(layer.payload, (bytes,)) and layer.payload is not None else None

    # If no Raw layer found but there's a transport payload
    if result["payload"] is None:
        for layer_cls in (TCP, UDP):
            if raw_pkt.haslayer(layer_cls):
                payload_data = raw_pkt[layer_cls].payload
                if payload_data is not None:
                    payload_bytes = bytes(payload_data)
                    if len(payload_bytes) > 0:
                        result["payload"] = {
                            "length": len(payload_bytes),
                            "hexdump": _format_hexdump(payload_bytes),
                        }
                break

    # Run profile-specified addons (protocol parsers)
    if profile:
        from .addon_loader import run_addons
        result["addons"] = run_addons(raw_pkt, profile)

    return result


def _get_direction(pkt, profile, local_ip):
    """Determine packet direction from profile ports and/or local IP."""
    from scapy.layers.inet import IP, TCP, UDP

    direction = {"label": None, "by_profile": None, "by_ip": None}

    src_ip = dst_ip = None
    src_port = dst_port = None
    proto = None

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        proto = "tcp"
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        proto = "udp"

    # Profile-based direction
    if profile and proto and (src_port or dst_port):
        server_ports = set()
        for port in profile.ports.get(proto, []):
            server_ports.add(port)
        for r in profile.port_ranges.get(proto, []):
            for p in range(r["start"], r["end"] + 1):
                server_ports.add(p)

        if dst_port in server_ports and src_port not in server_ports:
            direction["by_profile"] = "Client \u2192 Server"
        elif src_port in server_ports and dst_port not in server_ports:
            direction["by_profile"] = "Server \u2192 Client"
        elif dst_port in server_ports and src_port in server_ports:
            direction["by_profile"] = "Server \u2194 Server"

    # IP-based direction
    if local_ip and src_ip and dst_ip:
        if src_ip == local_ip:
            direction["by_ip"] = "Outbound"
        elif dst_ip == local_ip:
            direction["by_ip"] = "Inbound"

    # Combined label
    parts = [p for p in [direction["by_profile"], direction["by_ip"]] if p]
    direction["label"] = " / ".join(parts) if parts else None

    return direction


def _format_hexdump(data, width=16):
    """Format bytes as Wireshark-style hex dump."""
    lines = []
    for offset in range(0, len(data), width):
        chunk = data[offset:offset + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk[:8])
        if len(chunk) > 8:
            hex_part += "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:04x}   {hex_part:<49s}  {ascii_part}")
    return "\n".join(lines)
