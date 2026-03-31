# PacketSpy

A Windows packet sniffer that tracks network traffic by application. Create profiles to monitor specific apps (games, servers, clients) or watch all local network traffic through a browser-based dashboard.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

![screenshot](https://raw.githubusercontent.com/xJeris/packetspy/refs/heads/main/sample.png)

## Features

- **Live packet capture** with Npcap in promiscuous mode
- **Per-application tracking** — map packets to processes via Windows API
- **Profile system** — YAML configs that define which apps/ports/IPs to monitor
- **BPF filtering** — kernel-level packet filtering, auto-generated from profiles
- **Packet inspector** — click any packet to see full protocol layers, hex dump, and traffic direction (modal or side panel view)
- **TCP flag expansion** — human-readable flag names (SYN, ACK, PSH, etc.) with contextual descriptions (e.g., "Connection accepted (handshake step 2)")
- **Stream tracking** — group TCP and UDP packets into bidirectional conversations
- **Follow Stream** — Wireshark-style conversation view with hex dump or plain text, client/server direction coloring
- **Real-time dashboard** — protocol breakdown, top processes, top talkers
- **PCAP save/load** — save captures in Wireshark-compatible format and load them back for review
- **Addon system** — pluggable protocol parsers with per-flow context and optional statefulness (e.g., EverQuest session protocol decoder with opcode labeling, CRC stripping, and decompression)
- **Protocol discovery** — reverse-engineer unknown protocols: group packets by 2-byte opcode, auto-detect field types (floats, strings, counters, length-prefixed data), baseline diffing to isolate opcodes triggered by specific actions
- **Browser UI** — dark-themed, tabbed interface served locally via Flask

## Quick Start

1. Install [Npcap](https://npcap.com/#download) (check **"WinPcap API-compatible Mode"** during install)
2. Install [Python 3.12+](https://python.org)
3. Double-click `start.bat` (auto-elevates to admin, creates venv, installs deps, opens browser)

Or manually:

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000

> **Note:** Must run as Administrator for Npcap access.

## UI Tabs

| Tab | Description |
|-----|-------------|
| **All Traffic** | Live packet stream with SSE updates |
| **By Process** | Sidebar of processes sorted by traffic, click to filter |
| **Streams** | TCP and UDP conversations grouped by 5-tuple, with Follow Stream view |
| **Dashboard** | Protocol bars, top processes, top talkers |
| **Discovery** | Protocol reverse-engineering workbench — group packets by opcode, auto-detect field types, baseline diff to identify unknown opcodes |

## Packet Inspector

Click any packet row to view full details. Two view modes (configurable in Settings):

- **Modal** — overlay popup, good for focused inspection
- **Side panel** — persistent right panel that updates as you click rows, better for analysis workflows. Drag the left edge to resize.

## Profiles

YAML files in `profiles/` define what to capture. Example (`profiles/everquest.yaml`):

```yaml
name: EverQuest
processes:
  - eqgame.exe
ports:
  udp:
    - 9000
    - 9001
port_ranges:
  udp:
    - start: 7000
      end: 7500
addons:
  - eq_session
```

**Fields:**

| Field | Description |
|-------|-------------|
| `name` | Display name |
| `description` | Optional description |
| `processes` | Process names to match (case-insensitive) |
| `ports.tcp` / `ports.udp` | Specific port numbers |
| `port_ranges.tcp` / `port_ranges.udp` | Port ranges (`start`/`end`) |
| `source_ips` / `dest_ips` | IP addresses or CIDRs |
| `addons` | List of addon IDs to activate |
| `bpf_filter_override` | Manual BPF filter (overrides auto-generation) |

## PCAP Save & Load

- **Save PCAP** — exports all captured packets to a `.pcap` file in the `captures/` folder
- **Load PCAP** — opens a saved `.pcap` file and populates the UI. You can optionally apply a profile when loading to enable addon parsing on the loaded packets.

## Addons

Protocol-specific parsers live in `addons/`. Addons can be a single `.py` file or a folder package with `__init__.py`. PacketSpy discovers them at startup. Addons only run when the active profile lists them.

**Included addon:**

- `eq_session` — Parses the EverQuest (SOE) session protocol: session opcodes, sequence numbers, CRC stripping, XOR decode (encode pass 1/2), zlib decompression, fragment reassembly, and application opcode labeling via selectable opcode files. Ships with RoF2 opcode mappings (~350 opcodes); additional client versions can be added as JSON files in `opcode_files/eq_session/`. Includes decoded payload hex dump, color-coded byte regions in the raw hex dump, and a "DECRYPTED" badge when XOR decode is active. Supports the Discovery tab via `discovery_hooks()` for decoding packets through the full EQ pipeline before opcode grouping.

**Writing an addon:**

```python
ADDON_INFO = {
    "name": "My Protocol",      # Display name in packet detail UI
    "protocol": "udp",          # "udp", "tcp", or "any"
}

def parse(payload_bytes, packet_info, state=None, flow_ctx=None):
    """
    payload_bytes: raw transport layer payload (bytes)
    packet_info: {"src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
    state: optional state object from init() (None for stateless addons)
    flow_ctx: optional FlowContext with per-flow metadata and persistent
              store dict (flow_ctx.store[addon_id]) for cross-packet state

    Return {"fields": [{"name": str, "value": str}, ...], "notes": str}
    or None to skip this packet.

    Optional keys in the return dict:
    - "flags": list of str — badge labels shown in the addon header (e.g., ["decrypted"])
    - "decoded_payload": hex str — processed payload bytes, shown as a hex dump in the addon section
    - "byte_regions": list of {"start": int, "end": int, "type": str} — color-codes byte ranges in the raw hex dump
    """
    if not payload_bytes:
        return None
    return {
        "fields": [{"name": "Example", "value": "Hello"}],
        "notes": "Parsed successfully",
    }

# Optional: stateful addon — return initial state
def init():
    return {}

# Optional: Discovery tab integration
def discovery_hooks():
    """Return hooks for the Discovery tab's protocol analysis."""
    return {
        "decode": my_decode_function,   # (raw_bytes, flow_ctx) -> clean_bytes | None
        "known_opcodes": {0x01: "OP_Example"},  # opcodes to label in discovery
    }
```

Addons can be single files (`addons/my_addon.py`) or packages (`addons/my_addon/__init__.py` with helper modules). Add the addon ID (folder or file name without `.py`) to a profile's `addons` list.

## Tech Stack

| Component | Library |
|-----------|---------|
| Packet capture | Scapy + Npcap |
| Process mapping | psutil |
| Profile config | PyYAML |
| Web UI | Flask |

## Project Structure

```
packetspy/
  app.py                  # Entrypoint (admin check, Npcap init, addon discovery)
  start.bat               # One-click launcher
  requirements.txt        # Python dependencies
  .gitignore              # Git exclusions
  packetspy/
    capture.py            # Capture engine (Scapy sniff thread)
    dissect.py            # Packet dissection + detail view
    process_mapper.py     # PID-to-port mapping via Windows API
    profile_loader.py     # YAML profile parser
    profile_matcher.py    # Packet-to-profile matching
    stats.py              # Live traffic statistics
    tcp_streams.py        # TCP and UDP stream tracker
    addon_loader.py       # Addon discovery and execution
    flow_context.py       # Per-flow context tracking for addons
    discovery.py          # Protocol discovery engine (opcode grouping, field analysis, baseline diffing)
    pcap_io.py            # PCAP save/load
    web/
      __init__.py         # Flask app factory
      routes.py           # API endpoints + SSE streaming
      templates/
        index.html        # Dashboard HTML
      static/
        app.js            # Frontend logic
        style.css         # Dark theme styles
  addons/
    eq_session/           # EverQuest session protocol parser (multi-file)
      __init__.py         # Addon entry point (stateful parse)
      opcodes.py          # Dynamic opcode file loader
      session_state.py    # Per-flow session state tracker
      crc.py              # CRC byte stripping
      decode.py           # XOR encode pass 1/2 decoder
      decompress.py       # Zlib raw deflate wrapper
  opcode_files/
    eq_session/
      RoF2.json           # RoF2 app-layer opcode mappings
  profiles/
    everquest.yaml        # EQ profile
```

## Requirements

- Windows 10/11
- Python 3.12+
- [Npcap](https://npcap.com/#download) with WinPcap API-compatible mode
- Administrator privileges
