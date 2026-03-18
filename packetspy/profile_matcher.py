"""Profile-to-packet matching with IP/CIDR support."""

import ipaddress


def packet_matches_profile(pkt: dict, profile) -> bool:
    """Return True if a parsed packet dict matches the given Profile rules.

    Matching logic:
    - Process match alone is sufficient (catches unexpected ports)
    - Port/IP match alone is sufficient (catches traffic before PID resolves)
    - If no rules defined at all, returns False
    """
    if not profile:
        return False

    # Process check — sufficient on its own
    if profile.processes:
        proc = (pkt.get("process") or "").lower()
        if proc and any(p == proc for p in profile.processes):
            return True

    # Port check
    proto = (pkt.get("protocol") or "").lower()
    if proto in ("tcp", "udp"):
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")

        for port in profile.ports.get(proto, []):
            if src_port == port or dst_port == port:
                return True

        for r in profile.port_ranges.get(proto, []):
            if src_port and r["start"] <= src_port <= r["end"]:
                return True
            if dst_port and r["start"] <= dst_port <= r["end"]:
                return True

    # IP check
    if _check_ip_match(pkt.get("src_ip"), profile.source_ips):
        return True
    if _check_ip_match(pkt.get("dst_ip"), profile.dest_ips):
        return True

    return False


def _check_ip_match(ip_str: str, cidr_list: list) -> bool:
    if not ip_str or not cidr_list:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if addr in net:
                return True
        except ValueError:
            if ip_str == cidr:
                return True
    return False
