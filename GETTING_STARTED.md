# Getting Started with PacketSpy

## Prerequisites

### 1. Install Npcap

PacketSpy uses Npcap for raw packet capture. Download it from [npcap.com](https://npcap.com/#download).

During installation, **you must check:**

- **"Install Npcap in WinPcap API-compatible Mode"**

This is required for Scapy to find the capture library.

### 2. Install Python

Download Python 3.12 or later from [python.org](https://www.python.org/downloads/).

During installation, check **"Add Python to PATH"**.

### 3. Administrator Access

PacketSpy must run as Administrator to access Npcap and capture network traffic. The included `start.bat` handles elevation automatically.

---

## Installation

### Option A: Use start.bat (recommended)

Double-click `start.bat`. It will:

1. Request admin privileges (UAC prompt)
2. Check that Npcap is installed (opens the download page if not)
3. Check that Python is available
4. Create a virtual environment and install dependencies (first run only)
5. Start the PacketSpy server
6. Open your browser to http://127.0.0.1:5000

### Option B: Manual setup

Open an **Administrator** command prompt and run:

```
cd path\to\packetspy
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

---

## Your First Capture

### Capturing all traffic

1. In the PacketSpy UI, select your network interface from the dropdown (look for one with your IP address)
2. Leave the Profile dropdown on "No Profile"
3. Click **Start**
4. Packets will stream in real-time on the All Traffic tab

### Capturing with a profile

1. Select your network interface
2. Select a profile (e.g., "EverQuest") from the Profile dropdown
3. Click **Start**
4. Only traffic matching the profile's ports/processes will be captured (BPF filter is auto-generated)

### Inspecting a packet

Click any row in the packet table to open the packet detail view. Two view modes are available (configurable in Settings):

- **Modal (overlay)** — a popup dialog, good for focused inspection
- **Side panel** — a persistent panel on the right that updates as you click rows, better for analysis workflows

Both views show:

- **Direction** — Client/Server (from profile ports) and Inbound/Outbound (from your IP)
- **Layers** — Collapsible protocol headers (Ethernet, IP, TCP/UDP). TCP layers include a flags description with human-readable names and context (e.g., "PSH ACK — Delivering data")
- **Addon sections** — Protocol-specific parsing (e.g., EQ Session Protocol shows opcodes, sequence numbers)
- **Payload** — Hex dump of the raw payload bytes

### Saving and loading captures

**Save:** Click the **Save PCAP** button to export captured packets as a `.pcap` file (Wireshark-compatible). Files are saved to the `captures/` folder.

**Load:** Click the **Load PCAP** button to open a previously saved `.pcap` file. A prompt lets you optionally apply a profile, which enables addon parsing on the loaded packets. Process information is not available in loaded captures (PID data isn't stored in PCAP files).

---

## UI Overview

### Tabs

**All Traffic** — Live packet stream. Each row shows: packet number, timestamp, source, destination, protocol, length, process name, and info summary. TCP flags are shown in expanded form (e.g., `[PSH ACK]` instead of `[PA]`).

**By Process** — Left sidebar lists processes sorted by traffic volume. Click a process to see only its packets.

**Streams** — Groups TCP and UDP packets into bidirectional conversations. Shows protocol, source/destination, packet count, bytes, duration, and connection state (ACTIVE/FIN/RST for TCP). Click a stream to see its packets, then click **Follow Stream** for a Wireshark-style conversation view with hex dump or plain text display and client/server direction coloring.

**Dashboard** — Real-time statistics: total packets/bytes, throughput rate, protocol breakdown (bar chart), top processes, and top talkers (IPs by volume).

### Controls

| Control | Action |
|---------|--------|
| Interface dropdown | Select which network adapter to capture on |
| Profile dropdown | Select an app profile or "No Profile" for all traffic |
| **Start** | Begin capturing |
| **Stop** | Stop capturing (packets remain in the table) |
| **Save PCAP** | Export to PCAP file |
| **Load PCAP** | Load a saved PCAP file for review |
| **Clear** | Remove all packets from the table |
| Gear icon | Settings: auto-scroll, auto-clear, detail view mode |
| **Shutdown** | Stop the server entirely |

### Settings

| Setting | Description |
|---------|-------------|
| Auto-scroll | Scroll to the latest packet as they arrive |
| Auto-clear | Clear packets automatically when starting a new capture |
| Packet detail view | Choose between **Modal** (overlay popup) or **Side panel** (persistent right panel) |

---

## Creating a Profile

Profiles are YAML files in the `profiles/` folder. Create a new `.yaml` file to monitor a specific application.

Profile names must be **20 characters or fewer** and contain only **letters, numbers, and underscores** (no spaces or special characters).

### Minimal example

```yaml
name: MyApp
processes:
  - myapp.exe
ports:
  tcp:
    - 8080
```

This captures TCP port 8080 traffic and tags packets from `myapp.exe`.

### Full example

```yaml
name: MyGame
description: Custom game server and client traffic

processes:
  - gameclient.exe
  - gameserver.exe

ports:
  tcp:
    - 3724
    - 8085
  udp:
    - 3724

port_ranges:
  udp:
    - start: 10000
      end: 10100

source_ips:
  - 192.168.1.0/24

dest_ips:
  - 10.0.0.50

addons:
  - my_protocol_addon

bpf_filter_override: null
```

### Profile fields reference

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Display name (max 20 chars, letters, numbers, and underscores only) |
| `description` | No | What this profile monitors |
| `processes` | No | List of process names (case-insensitive) |
| `ports.tcp` | No | List of TCP port numbers |
| `ports.udp` | No | List of UDP port numbers |
| `port_ranges.tcp` | No | TCP port ranges (`start`, `end`) |
| `port_ranges.udp` | No | UDP port ranges |
| `source_ips` | No | Source IP addresses or CIDRs |
| `dest_ips` | No | Destination IP addresses or CIDRs |
| `addons` | No | Addon IDs to activate |
| `bpf_filter_override` | No | Manual BPF string; set `null` to auto-generate |

At least one of `processes`, `ports`, `port_ranges`, or IP fields should be specified so a BPF filter can be generated. If none are set, all traffic is captured (same as no profile).

---

## Writing an Addon

Addons are protocol-specific parsers that add extra sections to the packet inspector. They live in the `addons/` folder as single `.py` files or as packages (folders with `__init__.py`).

### Stateless addon (single file)

Create `addons/my_protocol.py`:

```python
ADDON_INFO = {
    "name": "My Protocol",      # Shown as section header in packet detail
    "protocol": "tcp",          # "tcp", "udp", or "any"
}


def parse(payload_bytes, packet_info, state=None, flow_ctx=None):
    """Parse the transport layer payload.

    Args:
        payload_bytes: Raw bytes from the TCP/UDP payload.
        packet_info: Dict with keys:
            src_ip, dst_ip, src_port, dst_port, protocol
        state: State object from init() (None for stateless addons).
        flow_ctx: FlowContext with per-flow metadata and a persistent
            store dict (flow_ctx.store[addon_id]). None if unavailable.

    Returns:
        Dict with "fields" and "notes", or None to skip.
    """
    if len(payload_bytes) < 4:
        return None

    msg_type = payload_bytes[0]
    msg_len = int.from_bytes(payload_bytes[1:3], "big")

    return {
        "fields": [
            {"name": "Message type", "value": f"0x{msg_type:02x}"},
            {"name": "Message length", "value": str(msg_len)},
        ],
        "notes": f"Type=0x{msg_type:02x} len={msg_len}",
    }
```

### Stateful addon (package)

For complex protocols that need to track session state across packets, create a package:

```
addons/
  my_session/
    __init__.py       # ADDON_INFO, init(), parse()
    session_state.py  # State class
    opcodes.py        # Lookup tables
```

`addons/my_session/__init__.py`:

```python
from .session_state import SessionState

ADDON_INFO = {
    "name": "My Session Protocol",
    "protocol": "udp",
}


def init():
    """Return initial state — called once at startup."""
    return SessionState()


def parse(payload_bytes, packet_info, state=None, flow_ctx=None):
    """Parse with flow context and session awareness."""
    if not payload_bytes:
        return None

    # Use flow_ctx for per-flow state (preferred)
    if flow_ctx is not None:
        store = flow_ctx.store.setdefault("my_session", {"packet_count": 0})
        store["packet_count"] += 1
        count = store["packet_count"]
    elif state is not None:
        # Fallback to legacy init() state
        session = state.get_or_create(packet_info)
        session.packet_count += 1
        count = session.packet_count
    else:
        count = 0

    return {
        "fields": [
            {"name": "Flow packets", "value": str(flow_ctx.packet_count if flow_ctx else "N/A")},
            {"name": "Session packets", "value": str(count)},
        ],
        "notes": f"Parsed with flow context ({count} session packets)",
    }
```

### Registering an addon

Add the addon ID (filename without `.py`, or folder name) to a profile's `addons` list:

```yaml
addons:
  - my_protocol
  - my_session
```

### Restarting

Addons are discovered at startup. After a restart you should see:

```
[PacketSpy] Loaded addon: my_protocol (My Protocol)
[PacketSpy] Loaded addon: my_session (My Session Protocol)
[PacketSpy] Addon discovery complete: 2 addon(s) loaded
```

### Addon contract

- `ADDON_INFO` (dict, required): Must have `name` (str) and `protocol` (str)
- `parse(payload_bytes, packet_info, state=None, flow_ctx=None)` (function, required): Must return a dict or `None`
- `init()` (function, optional): Return a state object for stateful addons; passed as 3rd arg to `parse()`
- `flow_ctx` (optional kwarg): A `FlowContext` object automatically provided per network flow. Contains:
  - `flow_ctx.flow_key` — normalized 5-tuple identifying the flow
  - `flow_ctx.packet_count` — total packets seen in this flow
  - `flow_ctx.first_seen` / `flow_ctx.last_seen` — timestamps
  - `flow_ctx.store` — dict for addon-private state; use `flow_ctx.store[addon_id]` to persist data across packets in the same flow
- Addons that don't declare `flow_ctx` in their `parse()` signature still work — it simply won't be passed
- Return `None` to skip packets your addon doesn't handle
- The `protocol` field filters which packets your addon sees: `"udp"` means only UDP payloads are passed, `"tcp"` means only TCP, `"any"` means both
- Addons have no Scapy dependency — they receive raw `bytes` and return plain dicts
- If an addon raises an exception, it's caught and logged; other addons still run
- Flow state is automatically cleared when a new capture starts

### Removing an addon

Delete the file/folder from `addons/` or remove it from the profile's `addons` list. No code changes needed.

---

## Troubleshooting

### "Npcap is not installed" error

Install Npcap from [npcap.com](https://npcap.com/#download). Make sure to check **"WinPcap API-compatible Mode"** during installation.

### No interfaces appear in the dropdown

- Verify you're running as Administrator
- Verify Npcap is installed with WinPcap compatibility mode
- Try restarting after installing Npcap

### No packets appear after clicking Start

- Check that you selected the correct interface (the one with your active IP address)
- If using a profile, ensure the target application is running and generating traffic on the expected ports
- Try without a profile first to verify basic capture works

### Packet detail shows no addon section

- Verify a profile with `addons` is selected
- Check the console for `[PacketSpy] Loaded addon: ...` messages
- Addon only appears on packets matching the addon's protocol (e.g., UDP addon won't appear on TCP packets)

### Process column is empty

The process mapper refreshes every 2 seconds. Short-lived connections may close before the PID can be resolved. This is a known limitation of port-to-PID mapping.

### Loaded PCAP shows no process names

This is expected. PCAP files don't contain PID/process data — only raw packets. Process names are only available during live capture.
