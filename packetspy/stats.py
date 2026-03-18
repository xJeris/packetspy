"""Live traffic statistics aggregator."""

import threading
import time
from collections import defaultdict


class TrafficStats:
    """Thread-safe traffic counters updated per-packet."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.total_bytes = 0
            self.total_packets = 0
            self.start_time = time.time()
            self.by_protocol = defaultdict(lambda: {"packets": 0, "bytes": 0})
            self.by_process = defaultdict(lambda: {"packets": 0, "bytes": 0})
            self.by_ip = defaultdict(
                lambda: {"packets": 0, "bytes": 0, "as_src": 0, "as_dst": 0}
            )

    def update(self, parsed_pkt: dict):
        """Called for every parsed packet dict."""
        length = parsed_pkt.get("length", 0)
        protocol = parsed_pkt.get("protocol", "OTHER")
        process = parsed_pkt.get("process") or "Unknown"
        src_ip = parsed_pkt.get("src_ip")
        dst_ip = parsed_pkt.get("dst_ip")

        with self._lock:
            self.total_bytes += length
            self.total_packets += 1

            self.by_protocol[protocol]["packets"] += 1
            self.by_protocol[protocol]["bytes"] += length

            self.by_process[process]["packets"] += 1
            self.by_process[process]["bytes"] += length

            if src_ip:
                self.by_ip[src_ip]["packets"] += 1
                self.by_ip[src_ip]["bytes"] += length
                self.by_ip[src_ip]["as_src"] += 1
            if dst_ip:
                self.by_ip[dst_ip]["packets"] += 1
                self.by_ip[dst_ip]["bytes"] += length
                self.by_ip[dst_ip]["as_dst"] += 1

    def snapshot(self) -> dict:
        """Return a JSON-serializable snapshot of current stats."""
        with self._lock:
            elapsed = time.time() - self.start_time

            top_talkers = sorted(
                self.by_ip.items(),
                key=lambda x: x[1]["bytes"],
                reverse=True,
            )[:10]

            top_processes = sorted(
                self.by_process.items(),
                key=lambda x: x[1]["bytes"],
                reverse=True,
            )[:10]

            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "elapsed_seconds": round(elapsed, 1),
                "bytes_per_second": round(
                    self.total_bytes / max(elapsed, 0.1), 0
                ),
                "by_protocol": dict(self.by_protocol),
                "by_process": [
                    {"name": k, **dict(v)} for k, v in top_processes
                ],
                "top_talkers": [
                    {"ip": ip, **dict(data)} for ip, data in top_talkers
                ],
            }
