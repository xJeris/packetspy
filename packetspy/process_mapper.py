import socket
import threading

import psutil


class ProcessMapper:
    def __init__(self, refresh_interval=2.0):
        self._port_map = {}  # (port, proto) -> {"pid": int, "name": str}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._refresh_interval = refresh_interval
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._refresh()
        self._thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _refresh_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(self._refresh_interval)
            if not self._stop_event.is_set():
                self._refresh()

    def _refresh(self):
        new_map = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr and conn.pid:
                    port = conn.laddr.port
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    try:
                        proc = psutil.Process(conn.pid)
                        name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = f"PID:{conn.pid}"
                    new_map[(port, proto)] = {"pid": conn.pid, "name": name}
        except psutil.AccessDenied:
            pass
        with self._lock:
            self._port_map = new_map

    def lookup(self, port, proto="tcp"):
        """Look up a local port. Returns {"pid": int, "name": str} or None."""
        with self._lock:
            return self._port_map.get((port, proto.lower()))

    def enrich_packet(self, parsed_pkt):
        """Add process info to a parsed packet dict (in-place)."""
        proto = parsed_pkt.get("protocol", "").lower()
        if proto not in ("tcp", "udp"):
            return

        # Check source port (outbound from local process)
        info = self.lookup(parsed_pkt["src_port"], proto)
        if info:
            parsed_pkt["process"] = info["name"]
            parsed_pkt["pid"] = info["pid"]
            return

        # Check dest port (inbound to local process)
        info = self.lookup(parsed_pkt["dst_port"], proto)
        if info:
            parsed_pkt["process"] = info["name"]
            parsed_pkt["pid"] = info["pid"]
