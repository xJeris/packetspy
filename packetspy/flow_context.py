"""Per-flow context tracking for the addon system.

FlowContext provides addons with metadata about the current network flow
(packet count, timestamps) and a per-addon key-value store that persists
across packets in the same flow.

FlowTracker manages FlowContext instances keyed by normalized 5-tuple,
with automatic eviction of the oldest flows when the cap is reached.
"""

import threading
import time


class FlowContext:
    """State container for a single network flow, passed to addons."""

    __slots__ = ("flow_key", "packet_count", "first_seen", "last_seen", "store")

    def __init__(self, flow_key):
        self.flow_key = flow_key
        self.packet_count = 0
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.store = {}

    def touch(self):
        """Update timestamps and packet counter. Called by FlowTracker."""
        self.packet_count += 1
        self.last_seen = time.time()


class FlowTracker:
    """Manages FlowContext instances keyed by normalized 5-tuple."""

    def __init__(self, max_flows=10000):
        self._lock = threading.Lock()
        self._flows = {}
        self._max_flows = max_flows

    def get_or_create(self, packet_info):
        """Look up or create a FlowContext for the given packet_info dict.

        packet_info must contain: src_ip, dst_ip, src_port, dst_port, protocol.
        Returns the FlowContext with packet_count and last_seen already updated.
        """
        key = self._make_key(packet_info)
        if key is None:
            return None

        with self._lock:
            ctx = self._flows.get(key)
            if ctx is None:
                if len(self._flows) >= self._max_flows:
                    oldest_key = min(
                        self._flows, key=lambda k: self._flows[k].last_seen
                    )
                    del self._flows[oldest_key]
                ctx = FlowContext(key)
                self._flows[key] = ctx

            ctx.touch()
            return ctx

    def reset(self):
        """Clear all tracked flows."""
        with self._lock:
            self._flows.clear()

    @staticmethod
    def _make_key(packet_info):
        """Normalize 5-tuple so both directions map to the same flow."""
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        src_port = packet_info.get("src_port")
        dst_port = packet_info.get("dst_port")
        protocol = (packet_info.get("protocol") or "").upper()

        if not src_ip or not dst_ip:
            return None

        a = (src_ip, src_port or 0, dst_ip, dst_port or 0, protocol)
        b = (dst_ip, dst_port or 0, src_ip, src_port or 0, protocol)
        return min(a, b)
