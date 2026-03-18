import time
from pathlib import Path

CAPTURES_DIR = Path("captures")


def save_pcap(packets, filename=None):
    """Save a list of raw Scapy packets to a .pcap file."""
    from scapy.all import wrpcap

    CAPTURES_DIR.mkdir(exist_ok=True)
    if filename is None:
        filename = f"capture_{int(time.time())}.pcap"
    filepath = CAPTURES_DIR / filename
    wrpcap(str(filepath), packets)
    return filepath


def load_pcap(filepath):
    """Load packets from a .pcap file. Returns list of Scapy packets."""
    from scapy.all import rdpcap

    return rdpcap(str(filepath))
