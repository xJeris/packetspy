"""Addon discovery and execution for PacketSpy.

Scans the addons/ folder at startup, imports each addon that
exposes ADDON_INFO and parse(), and provides run_addons() to
execute matching addons on packet detail requests.

Addons can be single .py files or packages (folders with __init__.py).
Addons can optionally define init() for stateful operation.
"""

import importlib.util
import os
import sys
import traceback

# Registry: addon_id -> {"module": module, "info": ADDON_INFO, "state": ...}
_addons = {}


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

    entry = {"module": mod, "info": info, "state": None}

    # Optional: stateful addon with init()
    if hasattr(mod, "init"):
        entry["state"] = mod.init()

    _addons[addon_id] = entry
    print(f"[PacketSpy] Loaded addon: {addon_id} ({info['name']})")


def get_registered_addons():
    """Return dict of registered addon IDs to their info."""
    return {aid: data["info"] for aid, data in _addons.items()}


def run_addons(raw_pkt, profile):
    """Run profile-specified addons against a raw Scapy packet.

    Returns a list of addon results (only those that returned data).
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
            result = addon["module"].parse(payload_bytes, packet_info, state)
            if result is not None:
                results.append({
                    "name": addon["info"]["name"],
                    "data": result,
                })
        except Exception:
            print(f"[PacketSpy] Addon {addon_id} raised an error:\n{traceback.format_exc()}")

    return results
