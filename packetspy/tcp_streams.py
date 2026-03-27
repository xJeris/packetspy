"""Stream tracking — groups packets into bidirectional conversations (TCP + UDP)."""

import threading
import time


class Stream:
    """A single network conversation (bidirectional)."""

    def __init__(self, stream_id, src_ip, src_port, dst_ip, dst_port, protocol):
        self.stream_id = stream_id
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.state = "ACTIVE"
        self.process = None
        self.packet_nums = []

    def to_dict(self) -> dict:
        return {
            "stream_id": self.stream_id,
            "src": f"{self.src_ip}:{self.src_port}",
            "dst": f"{self.dst_ip}:{self.dst_port}",
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "duration": round(self.last_seen - self.start_time, 2),
            "state": self.state,
            "process": self.process,
        }


class StreamTracker:
    """Tracks TCP and UDP streams keyed by normalized 5-tuple."""

    def __init__(self, max_streams=5000):
        self._lock = threading.Lock()
        self._streams = {}
        self._next_id = 1
        self._max_streams = max_streams

    def reset(self):
        with self._lock:
            self._streams.clear()
            self._next_id = 1

    def _make_key(self, src_ip, src_port, dst_ip, dst_port, protocol):
        """Normalize so both directions map to the same stream."""
        a = (src_ip, src_port, dst_ip, dst_port)
        b = (dst_ip, dst_port, src_ip, src_port)
        return (protocol,) + min(a, b)

    def process_packet(self, parsed_pkt: dict):
        """Feed a parsed packet. Returns stream_id for TCP/UDP, None otherwise."""
        protocol = parsed_pkt.get("protocol")
        if protocol not in ("TCP", "UDP"):
            return None

        src_ip = parsed_pkt.get("src_ip")
        dst_ip = parsed_pkt.get("dst_ip")
        src_port = parsed_pkt.get("src_port")
        dst_port = parsed_pkt.get("dst_port")

        if not all([src_ip, dst_ip, src_port, dst_port]):
            return None

        key = self._make_key(src_ip, src_port, dst_ip, dst_port, protocol)

        with self._lock:
            if key not in self._streams:
                if len(self._streams) >= self._max_streams:
                    oldest_key = min(
                        self._streams,
                        key=lambda k: self._streams[k].last_seen,
                    )
                    del self._streams[oldest_key]

                stream = Stream(
                    self._next_id, src_ip, src_port, dst_ip, dst_port, protocol
                )
                self._next_id += 1
                self._streams[key] = stream

            stream = self._streams[key]
            stream.packet_count += 1
            stream.total_bytes += parsed_pkt.get("length", 0)
            stream.last_seen = time.time()
            stream.packet_nums.append(parsed_pkt.get("num"))

            if parsed_pkt.get("process") and not stream.process:
                stream.process = parsed_pkt["process"]

            # TCP-only state detection (UDP has no connection state)
            if protocol == "TCP":
                raw_flags = parsed_pkt.get("flags_raw", "")
                if "F" in raw_flags:
                    stream.state = "FIN"
                if "R" in raw_flags:
                    stream.state = "RST"

            return stream.stream_id

    def get_streams(self, limit=100, sort_by="last_seen") -> list:
        """Return stream dicts sorted by the given field."""
        with self._lock:
            streams = list(self._streams.values())

        sort_keys = {
            "last_seen": lambda s: s.last_seen,
            "bytes": lambda s: s.total_bytes,
            "packets": lambda s: s.packet_count,
        }
        streams.sort(key=sort_keys.get(sort_by, sort_keys["last_seen"]), reverse=True)
        return [s.to_dict() for s in streams[:limit]]

    def get_stream_direction_endpoint(self, stream_id: int):
        """Return (src_ip, src_port) for the initiating side of the stream."""
        with self._lock:
            for stream in self._streams.values():
                if stream.stream_id == stream_id:
                    return (stream.src_ip, stream.src_port)
        return (None, None)

    def get_stream_protocol(self, stream_id: int):
        """Return the protocol ('TCP' or 'UDP') for a stream."""
        with self._lock:
            for stream in self._streams.values():
                if stream.stream_id == stream_id:
                    return stream.protocol
        return None

    def get_stream_packets(self, stream_id: int) -> list:
        """Return packet numbers belonging to a stream."""
        with self._lock:
            for stream in self._streams.values():
                if stream.stream_id == stream_id:
                    return list(stream.packet_nums)
        return []
