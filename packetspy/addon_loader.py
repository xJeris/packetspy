"""Addon discovery and execution for PacketSpy.

Scans the addons/ folder at startup, imports each addon that
exposes ADDON_INFO and parse(), and provides run_addons() to
execute matching addons on packet detail requests.

Addons can be single .py files or packages (folders with __init__.py).
Addons can optionally define init() for stateful operation.

Each addon's parse() receives:
  - payload_bytes: raw transport-layer payload
  - packet_info: dict with src_ip, dst_ip, src_port, dst_port, protocol
  - state: optional per-addon state object from init()
  - flow_ctx: optional FlowContext with per-flow metadata and a persistent
    store dict (flow_ctx.store[addon_id]) for cross-packet state
"""

import importlib.util
import inspect
import os
import sys
import traceback

from .flow_context import FlowTracker

# Registry: addon_id -> {"module": module, "info": ADDON_INFO, "state": ..., "accepts_flow_ctx": bool}
_addons = {}

# Module-level flow tracker shared across all addon invocations
_flow_tracker = FlowTracker()


def discover_addons(addons_dir=None):
    """Scan addons/ folder and register valid addon modules."""
    if addons_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        addons_dir = os.path.join(project_root, "addons")

    if not os.path.isdir(addons_dir):
        print(f"[PacketSpy] No addons directory found at {addons_dir}")
        return

    for entry in os.listdir(addons_dir):
        if entry.startswith("_") or entry.startswith("."):
            continue

        entry_path = os.path.join(addons_dir, entry)

        # Folder-based addon: addons/name/__init__.py
        if os.path.isdir(entry_path):
            init_file = os.path.join(entry_path, "__init__.py")
            if not os.path.isfile(init_file):
                continue
            addon_id = entry
            _load_addon_package(addon_id, entry_path, addons_dir)

        # Single-file addon: addons/name.py
        elif entry.endswith(".py"):
            addon_id = entry[:-3]
            _load_addon_file(addon_id, entry_path)

    print(f"[PacketSpy] Addon discovery complete: {len(_addons)} addon(s) loaded")


def _load_addon_file(addon_id, filepath):
    """Load a single-file addon."""
    try:
        spec = importlib.util.spec_from_file_location(f"addons.{addon_id}", filepath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _register_addon(addon_id, mod)
    except Exception as e:
        print(f"[PacketSpy] Failed to load addon {addon_id}: {e}")


def _load_addon_package(addon_id, package_dir, addons_dir):
    """Load a folder-based addon package."""
    try:
        # Add addons dir to sys.path so relative imports within the package work
        if addons_dir not in sys.path:
            sys.path.insert(0, addons_dir)

        init_file = os.path.join(package_dir, "__init__.py")
        spec = importlib.util.spec_from_file_location(
            f"addons.{addon_id}",
            init_file,
            submodule_search_locations=[package_dir],
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[f"addons.{addon_id}"] = mod
        spec.loader.exec_module(mod)
        _register_addon(addon_id, mod)
    except Exception as e:
        print(f"[PacketSpy] Failed to load addon {addon_id}: {e}")


def _register_addon(addon_id, mod):
    """Validate and register an addon module."""
    if not hasattr(mod, "ADDON_INFO") or not hasattr(mod, "parse"):
        print(f"[PacketSpy] Addon {addon_id} missing ADDON_INFO or parse(), skipping")
        return

    info = mod.ADDON_INFO
    if "name" not in info or "protocol" not in info:
        print(f"[PacketSpy] Addon {addon_id} has incomplete ADDON_INFO, skipping")
        return

    # Check if parse() accepts a flow_ctx parameter
    sig = inspect.signature(mod.parse)
    accepts_flow_ctx = "flow_ctx" in sig.parameters

    entry = {"module": mod, "info": info, "state": None,
             "accepts_flow_ctx": accepts_flow_ctx, "discovery_hooks": None}

    # Optional: stateful addon with init()
    if hasattr(mod, "init"):
        entry["state"] = mod.init()

    # Optional: discovery hooks for the Discovery tab
    if hasattr(mod, "discovery_hooks") and callable(mod.discovery_hooks):
        try:
            hooks = mod.discovery_hooks()
            if isinstance(hooks, dict) and "decode" in hooks:
                entry["discovery_hooks"] = hooks
                print(f"[PacketSpy]   -> {addon_id} has discovery hooks")
        except Exception as e:
            print(f"[PacketSpy]   -> {addon_id} discovery_hooks() failed: {e}")

    _addons[addon_id] = entry
    print(f"[PacketSpy] Loaded addon: {addon_id} ({info['name']})")


def get_registered_addons():
    """Return dict of registered addon IDs to their info."""
    return {aid: data["info"] for aid, data in _addons.items()}


def get_discovery_addons():
    """Return list of addons that have discovery hooks.

    Each entry: {"id": addon_id, "name": str, "protocol": str}
    """
    result = []
    for addon_id, data in _addons.items():
        if data["discovery_hooks"] is not None:
            result.append({
                "id": addon_id,
                "name": data["info"]["name"],
                "protocol": data["info"]["protocol"],
            })
    return result


def get_addon_discovery_hooks(addon_id):
    """Return the discovery hooks dict for an addon, or None."""
    entry = _addons.get(addon_id)
    if entry:
        return entry["discovery_hooks"]
    return None


def reset_flow_tracker():
    """Clear all tracked flow contexts. Call when capture restarts."""
    _flow_tracker.reset()


def run_addons(raw_pkt, profile):
    """Run profile-specified addons against a raw Scapy packet.

    Returns a list of addon results (only those that returned data).
    Also feeds decoded payloads into the active discovery session if one exists.
    """
    from scapy.layers.inet import IP, TCP, UDP

    if not profile or not getattr(profile, "addons", None):
        return []

    # Build packet_info dict
    packet_info = {
        "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None,
        "protocol": None,
    }

    if raw_pkt.haslayer(IP):
        packet_info["src_ip"] = raw_pkt[IP].src
        packet_info["dst_ip"] = raw_pkt[IP].dst
    if raw_pkt.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = raw_pkt[TCP].sport
        packet_info["dst_port"] = raw_pkt[TCP].dport
    elif raw_pkt.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = raw_pkt[UDP].sport
        packet_info["dst_port"] = raw_pkt[UDP].dport

    # Get or create flow context for this packet's flow
    flow_ctx = _flow_tracker.get_or_create(packet_info)

    results = []
    for addon_id in profile.addons:
        if addon_id not in _addons:
            continue

        addon = _addons[addon_id]
        addon_protocol = addon["info"]["protocol"].lower()

        # Protocol filter
        if addon_protocol != "any":
            if packet_info["protocol"] and packet_info["protocol"].lower() != addon_protocol:
                continue

        # Extract payload bytes for the matching transport layer
        payload_bytes = None
        if addon_protocol == "udp" and raw_pkt.haslayer(UDP):
            payload_bytes = bytes(raw_pkt[UDP].payload)
        elif addon_protocol == "tcp" and raw_pkt.haslayer(TCP):
            payload_bytes = bytes(raw_pkt[TCP].payload)
        elif addon_protocol == "any":
            if raw_pkt.haslayer(UDP):
                payload_bytes = bytes(raw_pkt[UDP].payload)
            elif raw_pkt.haslayer(TCP):
                payload_bytes = bytes(raw_pkt[TCP].payload)

        if not payload_bytes:
            continue

        try:
            state = addon["state"]
            if addon["accepts_flow_ctx"]:
                result = addon["module"].parse(
                    payload_bytes, packet_info, state, flow_ctx=flow_ctx
                )
            else:
                result = addon["module"].parse(payload_bytes, packet_info, state)
            if result is not None:
                results.append({
                    "name": addon["info"]["name"],
                    "data": result,
                })
        except Exception:
            print(f"[PacketSpy] Addon {addon_id} raised an error:\n{traceback.format_exc()}")

    return results


def _feed_discovery_raw(raw_pkt):
    """Feed raw transport payload into discovery session (no addon mode)."""
    import time as _time
    try:
        from .web.routes import get_discovery_session
    except ImportError:
        return
    from scapy.layers.inet import UDP, TCP

    session = get_discovery_session()
    if session is None or not session.active or session.addon_id is not None:
        return

    payload = None
    if raw_pkt.haslayer(UDP):
        payload = bytes(raw_pkt[UDP].payload)
    elif raw_pkt.haslayer(TCP):
        payload = bytes(raw_pkt[TCP].payload)

    if payload and len(payload) >= 2:
        session.ingest(payload, _time.time())


def feed_discovery(raw_pkt, profile):
    """Feed a packet into the active discovery session.

    Called from capture/PCAP-load paths. Handles both addon and raw modes.
    Should be called even when no profile is active.
    """
    import time as _time
    try:
        from .web.routes import get_discovery_session
    except ImportError:
        return

    session = get_discovery_session()
    if session is None or not session.active:
        return

    from scapy.layers.inet import IP, UDP, TCP

    if session.addon_id is None:
        # Raw mode — ingest transport payload directly
        _feed_discovery_raw(raw_pkt)
    elif session.addon_id in _addons:
        # Addon mode — need to decode first
        addon = _addons[session.addon_id]
        addon_protocol = addon["info"]["protocol"].lower()

        payload = None
        if addon_protocol == "udp" and raw_pkt.haslayer(UDP):
            payload = bytes(raw_pkt[UDP].payload)
        elif addon_protocol == "tcp" and raw_pkt.haslayer(TCP):
            payload = bytes(raw_pkt[TCP].payload)
        elif addon_protocol == "any":
            if raw_pkt.haslayer(UDP):
                payload = bytes(raw_pkt[UDP].payload)
            elif raw_pkt.haslayer(TCP):
                payload = bytes(raw_pkt[TCP].payload)

        if not payload or len(payload) < 2:
            return

        # Build packet_info for flow context
        packet_info = {
            "src_ip": None, "dst_ip": None,
            "src_port": None, "dst_port": None,
            "protocol": None,
        }
        if raw_pkt.haslayer(IP):
            packet_info["src_ip"] = raw_pkt[IP].src
            packet_info["dst_ip"] = raw_pkt[IP].dst
        if raw_pkt.haslayer(TCP):
            packet_info["protocol"] = "TCP"
            packet_info["src_port"] = raw_pkt[TCP].sport
            packet_info["dst_port"] = raw_pkt[TCP].dport
        elif raw_pkt.haslayer(UDP):
            packet_info["protocol"] = "UDP"
            packet_info["src_port"] = raw_pkt[UDP].sport
            packet_info["dst_port"] = raw_pkt[UDP].dport

        flow_ctx = _flow_tracker.get_or_create(packet_info)

        # If no profile is active, run parse() first so the addon can
        # accumulate session state (e.g. CRC bytes, encode key from
        # OP_SessionResponse) that the decode hook depends on.
        addon_in_profile = (
            profile and getattr(profile, "addons", None)
            and session.addon_id in profile.addons
        )
        if not addon_in_profile:
            try:
                state = addon["state"]
                if addon["accepts_flow_ctx"]:
                    addon["module"].parse(payload, packet_info, state, flow_ctx=flow_ctx)
                else:
                    addon["module"].parse(payload, packet_info, state)
            except Exception:
                pass

        hooks = addon["discovery_hooks"]
        if hooks and hooks.get("decode"):
            try:
                clean = hooks["decode"](payload, flow_ctx)
                if clean and len(clean) >= 2:
                    session.ingest(clean, _time.time())
            except Exception:
                pass
