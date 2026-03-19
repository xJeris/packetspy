# PacketSpy

A Windows packet sniffer that tracks network traffic by application. Create profiles to monitor specific apps (games, servers, clients) or watch all local network traffic through a browser-based dashboard.

## Features

- **Live packet capture** with Npcap in promiscuous mode
- **Per-application tracking** — map packets to processes via Windows API
- **Profile system** — YAML configs that define which apps/ports/IPs to monitor
- **BPF filtering** — kernel-level packet filtering, auto-generated from profiles
- **Packet inspector** — click any packet to see full protocol layers, hex dump, and traffic direction (modal or side panel view)
- **TCP stream tracking** — group packets into conversations
- **Real-time dashboard** — protocol breakdown, top processes, top talkers
- **PCAP save/load** — save captures in Wireshark-compatible format and load them back for review
- **Addon system** — pluggable protocol parsers with per-flow context and optional statefulness (e.g., EverQuest session protocol decoder with opcode labeling, CRC stripping, and decompression)
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
| **TCP Streams** | TCP conversations grouped by 5-tuple |
| **Dashboard** | Protocol bars, top processes, top talkers |

## Packet Inspector

Click any packet row to view full details. Two view modes (configurable in Settings):

- **Modal** — overlay popup, good for focused inspection
- **Side panel** — persistent right panel that updates as you click rows, better for analysis workflows

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

- `eq_session` — Parses the EverQuest (SOE) session protocol: session opcodes, sequence numbers, CRC stripping, zlib decompression, and application opcode labeling using ~350 RoF2 opcode mappings

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
    tcp_streams.py        # TCP conversation tracker
    addon_loader.py       # Addon discovery and execution
    flow_context.py       # Per-flow context tracking for addons
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
      opcodes.py          # RoF2 opcode hex→name mapping
      session_state.py    # Per-flow session state tracker
      crc.py              # CRC byte stripping
      decompress.py       # Zlib raw deflate wrapper
  profiles/
    everquest.yaml        # EQ profile
```

## Requirements

- Windows 10/11
- Python 3.12+
- [Npcap](https://npcap.com/#download) with WinPcap API-compatible mode
- Administrator privileges
