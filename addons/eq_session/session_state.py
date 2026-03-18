"""Per-flow session state tracking for EQ addon.

Stores CRC byte count and encode key learned from OP_SessionResponse
so subsequent packets in the same session can be properly parsed.
"""


class SessionState:
    def __init__(self):
        # (ip_a, ip_b) -> {"crc_bytes": int, "encode_key": int}
        self.sessions = {}

    def update(self, packet_info, crc_bytes, encode_key):
        """Store session parameters from OP_SessionResponse."""
        key = self._flow_key(packet_info)
        self.sessions[key] = {
            "crc_bytes": crc_bytes,
            "encode_key": encode_key,
        }

    def get(self, packet_info):
        """Get session parameters for this flow, or None."""
        return self.sessions.get(self._flow_key(packet_info))

    def _flow_key(self, pinfo):
        """Normalize IP pair so both directions map to same session."""
        src = pinfo.get("src_ip") or ""
        dst = pinfo.get("dst_ip") or ""
        return tuple(sorted([src, dst]))
