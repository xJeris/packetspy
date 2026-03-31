import collections
import queue
import threading

from .dissect import dissect_packet
from .stats import TrafficStats
from .tcp_streams import StreamTracker


def _resolve_iface(name):
    """Resolve an interface name to a Scapy interface object."""
    from scapy.all import conf

    if not name:
        return conf.iface
    # Try exact match by name
    for iface in conf.ifaces.values():
        if getattr(iface, "name", "") == name:
            return iface
    # Fallback to string (let Scapy try)
    return name


class CaptureEngine:
    def __init__(self):
        self.packet_buffer = collections.deque(maxlen=10000)
        self.raw_packets = []
        self._stop_event = threading.Event()
        self._thread = None
        self.is_running = False
        self.bpf_filter = None
        self.iface = None
        self.active_profile = None
        self.process_mapper = None
        self._packet_counter = 0
        self._sse_subscribers = []
        self.last_error = None
        self.stats = TrafficStats()
        self.stream_tracker = StreamTracker()

    def start(self, iface=None, bpf_filter=None):
        if self.is_running:
            return
        self._stop_event.clear()
        self.bpf_filter = bpf_filter
        self.iface = _resolve_iface(iface)
        self.last_error = None
        self.raw_packets.clear()
        self.packet_buffer.clear()
        self._packet_counter = 0
        self.stats.reset()
        self.stream_tracker.reset()
        from .addon_loader import reset_flow_tracker
        reset_flow_tracker()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        self.is_running = True

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self.is_running = False

    def _sniff_loop(self):
        from scapy.all import conf, sniff

        iface = self.iface
        print(f"[PacketSpy] Starting capture on: {iface}")
        print(f"[PacketSpy] Interface type: {type(iface)}")
        print(f"[PacketSpy] use_npcap: {conf.use_npcap}")
        if hasattr(iface, "pcap_name"):
            print(f"[PacketSpy] Npcap device: {iface.pcap_name}")
        if hasattr(iface, "guid"):
            print(f"[PacketSpy] GUID: {iface.guid}")
        print(f"[PacketSpy] BPF filter: {self.bpf_filter or '(none)'}")

        try:
            # Use short timeout loops so stop_event is checked between rounds
            while not self._stop_event.is_set():
                sniff(
                    iface=iface,
                    prn=self._handle_packet,
                    store=False,
                    promisc=True,
                    filter=self.bpf_filter if self.bpf_filter else None,
                    timeout=1,
                )
        except Exception as e:
            self.last_error = str(e)
            print(f"[PacketSpy] Capture error: {e}")
        finally:
            self.is_running = False

    def _handle_packet(self, pkt):
        self._packet_counter += 1
        self.raw_packets.append(pkt)

        parsed = dissect_packet(pkt, self._packet_counter)
        if parsed and self.process_mapper:
            self.process_mapper.enrich_packet(parsed)

        if parsed:
            self.stats.update(parsed)
            stream_id = self.stream_tracker.process_packet(parsed)
            if stream_id is not None:
                parsed["stream_id"] = stream_id

        # Run addons during capture so stateful addons (e.g. fragment
        # reassembly) can accumulate cross-packet state in flow_ctx.
        if self.active_profile:
            from .addon_loader import run_addons
            run_addons(pkt, self.active_profile)

        # Feed discovery session (works with or without profile)
        from .addon_loader import feed_discovery
        feed_discovery(pkt, self.active_profile)

        self.packet_buffer.append(parsed)

        for q in list(self._sse_subscribers):
            try:
                q.put_nowait(parsed)
            except queue.Full:
                pass

    def subscribe_sse(self):
        """Return a Queue that receives new packets for SSE streaming."""
        q = queue.Queue(maxsize=500)
        self._sse_subscribers.append(q)
        return q

    def unsubscribe_sse(self, q):
        try:
            self._sse_subscribers.remove(q)
        except ValueError:
            pass
