import json
import os
import signal
import queue

from flask import Blueprint, Response, current_app, jsonify, render_template, request

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/api/packets")
def get_packets():
    """Return recent packets from the buffer."""
    engine = current_app.config["capture_engine"]
    packets = list(engine.packet_buffer)
    return jsonify(packets)


@bp.route("/api/stream")
def stream():
    """SSE endpoint — streams new packets as they arrive."""
    engine = current_app.config["capture_engine"]
    q = engine.subscribe_sse()

    def generate():
        try:
            while True:
                try:
                    pkt = q.get(timeout=30)
                    yield f"data: {json.dumps(pkt)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            engine.unsubscribe_sse(q)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/api/capture/start", methods=["POST"])
def start_capture():
    engine = current_app.config["capture_engine"]
    mapper = current_app.config["process_mapper"]
    data = request.get_json(silent=True) or {}

    profile_name = data.get("profile")
    iface = data.get("iface")
    bpf_filter = None

    if profile_name:
        from ..profile_loader import ProfileValidationError, load_profile

        profiles_dir = current_app.config["profiles_dir"]
        try:
            profile = load_profile(f"{profiles_dir}/{profile_name}")
        except ProfileValidationError as e:
            return jsonify({"error": str(e)}), 400
        bpf_filter = profile.generate_bpf()
        engine.active_profile = profile
    else:
        engine.active_profile = None

    mapper.start()
    engine.start(iface=iface, bpf_filter=bpf_filter)

    return jsonify({
        "status": "started",
        "filter": bpf_filter,
        "profile": profile_name,
    })


@bp.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    engine = current_app.config["capture_engine"]
    mapper = current_app.config["process_mapper"]
    engine.stop()
    mapper.stop()
    return jsonify({"status": "stopped", "packet_count": engine._packet_counter})


@bp.route("/api/capture/status")
def capture_status():
    engine = current_app.config["capture_engine"]
    profile_data = None
    if engine.active_profile:
        profile_data = {
            "name": engine.active_profile.name,
            "processes": engine.active_profile.processes,
        }
    return jsonify({
        "running": engine.is_running,
        "packet_count": engine._packet_counter,
        "profile": engine.active_profile.name if engine.active_profile else None,
        "profile_data": profile_data,
        "filter": engine.bpf_filter,
        "error": engine.last_error,
    })


@bp.route("/api/profiles")
def list_profiles():
    from ..profile_loader import load_profile, list_profiles as _list_profiles

    profiles_dir = current_app.config["profiles_dir"]
    files = _list_profiles(profiles_dir)
    profiles = []
    for f in files:
        try:
            profile = load_profile(str(f))
            profiles.append({"filename": f.name, "name": profile.name})
        except Exception:
            # Skip profiles with validation errors
            profiles.append({"filename": f.name, "name": f.stem, "error": "Invalid profile"})
    return jsonify(profiles)


@bp.route("/api/pcap/save", methods=["POST"])
def save_pcap():
    from ..pcap_io import save_pcap as _save_pcap

    engine = current_app.config["capture_engine"]
    if not engine.raw_packets:
        return jsonify({"error": "No packets to save"}), 400

    data = request.get_json(silent=True) or {}
    filename = data.get("filename")
    filepath = _save_pcap(engine.raw_packets, filename)
    return jsonify({"status": "saved", "filename": str(filepath)})


@bp.route("/api/pcap/load", methods=["POST"])
def load_pcap_route():
    """Load a PCAP file — saves to temp, returns a load_id for SSE streaming."""
    import tempfile
    import uuid

    engine = current_app.config["capture_engine"]

    if engine.is_running:
        return jsonify({"error": "Stop capture before loading a file"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]

    # Save to temp location (cleaned up after streaming completes)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    f.save(tmp.name)
    tmp.close()

    # Apply profile if requested (enables addons on detail view)
    profile_name = request.form.get("profile")
    if profile_name:
        from ..profile_loader import ProfileValidationError, load_profile

        profiles_dir = current_app.config["profiles_dir"]
        try:
            engine.active_profile = load_profile(f"{profiles_dir}/{profile_name}")
        except ProfileValidationError as e:
            os.unlink(tmp.name)
            return jsonify({"error": str(e)}), 400
    else:
        engine.active_profile = None

    load_id = uuid.uuid4().hex[:12]
    _pending_loads = current_app.config.setdefault("_pending_loads", {})
    _pending_loads[load_id] = {"tmp_path": tmp.name, "filename": f.filename}

    return jsonify({"status": "ready", "load_id": load_id, "filename": f.filename})


@bp.route("/api/pcap/load/<load_id>/stream")
def stream_pcap_load(load_id):
    """SSE endpoint that streams parsed packets from a pending PCAP load."""
    from ..pcap_io import iter_pcap
    from ..dissect import dissect_packet
    from ..addon_loader import reset_flow_tracker, run_addons, feed_discovery

    engine = current_app.config["capture_engine"]
    _pending_loads = current_app.config.get("_pending_loads", {})
    load_info = _pending_loads.pop(load_id, None)

    if not load_info:
        return jsonify({"error": "Unknown or expired load_id"}), 404

    tmp_path = load_info["tmp_path"]
    filename = load_info["filename"]

    # Reset engine state
    engine.raw_packets.clear()
    engine.packet_buffer.clear()
    engine._packet_counter = 0
    engine.stats.reset()
    engine.stream_tracker.reset()
    reset_flow_tracker()

    CHUNK_SIZE = 200

    def generate():
        chunk = []
        try:
            for pkt in iter_pcap(tmp_path):
                engine._packet_counter += 1
                engine.raw_packets.append(pkt)

                parsed = dissect_packet(pkt, engine._packet_counter)
                if parsed:
                    if hasattr(pkt, "time") and pkt.time:
                        parsed["timestamp"] = float(pkt.time)
                    engine.stats.update(parsed)
                    stream_id = engine.stream_tracker.process_packet(parsed)
                    if stream_id is not None:
                        parsed["stream_id"] = stream_id

                if engine.active_profile:
                    run_addons(pkt, engine.active_profile)

                # Feed discovery session (works with or without profile)
                feed_discovery(pkt, engine.active_profile)

                engine.packet_buffer.append(parsed)
                if parsed:
                    chunk.append(parsed)

                if len(chunk) >= CHUNK_SIZE:
                    yield f"data: {json.dumps({'type': 'packets', 'packets': chunk})}\n\n"
                    chunk = []

            # Flush remaining
            if chunk:
                yield f"data: {json.dumps({'type': 'packets', 'packets': chunk})}\n\n"

            yield f"data: {json.dumps({'type': 'done', 'packet_count': engine._packet_counter, 'filename': filename})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@bp.route("/api/interfaces")
def list_interfaces():
    from scapy.all import conf

    # Filter out virtual/filter adapters that aren't useful for capture
    NOISE_KEYWORDS = (
        "WFP", "QoS", "LightWeight", "Packet Scheduler",
        "WAN Miniport", "Kernel Debug", "WiFi Filter Driver",
        "Teredo", "6to4", "IP-HTTPS", "ISATAP",
    )

    ifaces = []
    for iface in conf.ifaces.values():
        desc = getattr(iface, "description", "") or ""
        name = getattr(iface, "name", "") or ""
        if any(kw.lower() in desc.lower() for kw in NOISE_KEYWORDS):
            continue
        if any(kw.lower() in name.lower() for kw in NOISE_KEYWORDS):
            continue
        ip = getattr(iface, "ip", "") or ""
        ifaces.append({
            "name": name,
            "description": desc,
            "ip": ip,
        })
    return jsonify(ifaces)


@bp.route("/api/debug/interfaces")
def debug_interfaces():
    """Diagnostic endpoint — shows raw Scapy interface details."""
    from scapy.all import conf

    result = []
    for iface in conf.ifaces.values():
        result.append({
            "name": getattr(iface, "name", "?"),
            "description": getattr(iface, "description", "?"),
            "ip": getattr(iface, "ip", "?"),
            "mac": getattr(iface, "mac", "?"),
            "guid": getattr(iface, "guid", "?"),
            "pcap_name": getattr(iface, "pcap_name", "?"),
            "type": str(type(iface)),
            "index": getattr(iface, "index", "?"),
        })
    return jsonify({
        "default_iface": str(conf.iface),
        "use_npcap": conf.use_npcap,
        "interfaces": result,
    })


@bp.route("/api/stats")
def get_stats():
    """Return live traffic statistics snapshot."""
    engine = current_app.config["capture_engine"]
    return jsonify(engine.stats.snapshot())


@bp.route("/api/streams")
def get_streams():
    """Return active TCP and UDP streams."""
    engine = current_app.config["capture_engine"]
    sort_by = request.args.get("sort", "last_seen")
    limit = int(request.args.get("limit", 100))
    return jsonify(engine.stream_tracker.get_streams(limit=limit, sort_by=sort_by))


@bp.route("/api/streams/<int:stream_id>/packets")
def get_stream_packets(stream_id):
    """Return packets for a specific stream."""
    engine = current_app.config["capture_engine"]
    packet_nums = set(engine.stream_tracker.get_stream_packets(stream_id))
    packets = [p for p in engine.packet_buffer if p and p.get("num") in packet_nums]
    return jsonify(packets)


@bp.route("/api/streams/<int:stream_id>/conversation")
def get_stream_conversation(stream_id):
    """Return payload data for all packets in a stream, with direction."""
    from scapy.layers.inet import IP, TCP, UDP

    engine = current_app.config["capture_engine"]
    packet_nums = engine.stream_tracker.get_stream_packets(stream_id)
    if not packet_nums:
        return jsonify([])

    stream_src, stream_src_port = engine.stream_tracker.get_stream_direction_endpoint(stream_id)
    stream_proto = engine.stream_tracker.get_stream_protocol(stream_id)

    result = []
    for num in packet_nums:
        if num < 1 or num > len(engine.raw_packets):
            continue
        raw_pkt = engine.raw_packets[num - 1]

        # Get the transport layer (TCP or UDP)
        if stream_proto == "TCP" and raw_pkt.haslayer(TCP):
            transport = raw_pkt[TCP]
        elif stream_proto == "UDP" and raw_pkt.haslayer(UDP):
            transport = raw_pkt[UDP]
        else:
            continue

        ip_layer = raw_pkt[IP] if raw_pkt.haslayer(IP) else None

        src_ip = ip_layer.src if ip_layer else None
        dst_ip = ip_layer.dst if ip_layer else None
        src_port = transport.sport
        dst_port = transport.dport

        is_client = (src_ip == stream_src and src_port == stream_src_port)

        payload_bytes = bytes(transport.payload) if transport.payload else b""

        payload_hex = payload_bytes.hex() if payload_bytes else ""
        payload_text = "".join(
            chr(b) if 32 <= b < 127 else "." for b in payload_bytes
        ) if payload_bytes else ""

        ts = float(raw_pkt.time) if hasattr(raw_pkt, "time") and raw_pkt.time else None
        flags_raw = ""
        if ts is None or stream_proto == "TCP":
            for p in engine.packet_buffer:
                if p and p.get("num") == num:
                    if ts is None:
                        ts = p.get("timestamp")
                    flags_raw = p.get("flags_raw", "")
                    break

        result.append({
            "num": num,
            "timestamp": ts,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "direction": "client" if is_client else "server",
            "flags_raw": flags_raw,
            "payload_hex": payload_hex,
            "payload_text": payload_text,
            "payload_len": len(payload_bytes),
            "has_payload": len(payload_bytes) > 0,
        })

    return jsonify(result)


@bp.route("/api/packets/by_process")
def get_packets_by_process():
    """Return packets filtered by process name."""
    engine = current_app.config["capture_engine"]
    process_filter = request.args.get("process")
    packets = list(engine.packet_buffer)
    if process_filter:
        packets = [p for p in packets if p and (p.get("process") or "Unknown") == process_filter]
    return jsonify(packets)


@bp.route("/api/packets/<int:num>/detail")
def get_packet_detail(num):
    """Return full detail for a single packet by sequence number."""
    from ..dissect import dissect_packet_detail

    engine = current_app.config["capture_engine"]
    if num < 1 or num > len(engine.raw_packets):
        return jsonify({"error": "Packet not found"}), 404

    raw_pkt = engine.raw_packets[num - 1]

    # Find parsed packet from buffer for enriched info
    parsed_pkt = None
    for p in engine.packet_buffer:
        if p and p.get("num") == num:
            parsed_pkt = p
            break
    if not parsed_pkt:
        parsed_pkt = {"num": num, "timestamp": None, "length": len(raw_pkt),
                       "process": None, "pid": None}

    # Get local IP from capture interface
    local_ip = None
    if engine.iface and hasattr(engine.iface, "ip"):
        local_ip = engine.iface.ip

    detail = dissect_packet_detail(
        raw_pkt, parsed_pkt,
        profile=engine.active_profile,
        local_ip=local_ip,
    )
    return jsonify(detail)


@bp.route("/api/packets/by_profile")
def get_packets_by_profile():
    """Return packets filtered by the active profile rules."""
    from ..profile_matcher import packet_matches_profile

    engine = current_app.config["capture_engine"]
    if not engine.active_profile:
        return jsonify({"error": "No active profile"}), 400
    packets = [p for p in engine.packet_buffer
               if p and packet_matches_profile(p, engine.active_profile)]
    return jsonify(packets)


SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "settings.json")

DEFAULT_SETTINGS = {
    "autoScroll": True,
    "autoClear": False,
    "detailView": "modal",
}


def _load_settings():
    try:
        with open(SETTINGS_FILE, "r") as f:
            saved = json.load(f)
        return {**DEFAULT_SETTINGS, **saved}
    except (FileNotFoundError, json.JSONDecodeError):
        return dict(DEFAULT_SETTINGS)


def _save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


@bp.route("/api/settings", methods=["GET"])
def get_settings():
    return jsonify(_load_settings())


@bp.route("/api/settings", methods=["PUT"])
def put_settings():
    data = request.get_json(silent=True) or {}
    settings = _load_settings()
    for key in DEFAULT_SETTINGS:
        if key in data:
            settings[key] = data[key]
    _save_settings(settings)
    return jsonify(settings)


# ---------------------------------------------------------------------------
# Opcode files API
# ---------------------------------------------------------------------------


def _safe_name(name):
    """Sanitize a name for use as a filename component (no path traversal)."""
    return "".join(c for c in name if c.isalnum() or c in "_-")


def _opcode_files_dir(addon_id):
    """Return the directory for opcode files of a given addon (or 'raw')."""
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    name = _safe_name(addon_id) if addon_id else "raw"
    if not name:
        name = "raw"
    d = os.path.join(project_root, "opcode_files", name)
    os.makedirs(d, exist_ok=True)
    return d


@bp.route("/api/opcode-files/<addon_id>")
def opcode_files_list(addon_id):
    """List available opcode files for an addon."""
    d = _opcode_files_dir(addon_id)
    result = []
    for entry in sorted(os.listdir(d)):
        if entry.endswith(".json"):
            file_id = entry[:-5]
            path = os.path.join(d, entry)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                count = len(data)
            except (json.JSONDecodeError, OSError):
                count = 0
            result.append({"id": file_id, "name": file_id, "count": count})
    return jsonify(result)


@bp.route("/api/opcode-files/<addon_id>/active")
def opcode_files_get_active(addon_id):
    """Get the currently active opcode file for an addon."""
    if addon_id == "eq_session":
        try:
            from addons.eq_session.opcodes import get_active_file_id
            return jsonify({"file_id": get_active_file_id()})
        except ImportError:
            pass
    return jsonify({"file_id": None})


@bp.route("/api/opcode-files/<addon_id>/active", methods=["PUT"])
def opcode_files_set_active(addon_id):
    """Set the active opcode file for an addon."""
    data = request.get_json(silent=True) or {}
    file_id = data.get("file_id")

    if not file_id:
        # Clear active opcodes
        if addon_id == "eq_session":
            try:
                from addons.eq_session.opcodes import set_active_opcodes_dict
                set_active_opcodes_dict({}, None)
            except ImportError:
                pass
        return jsonify({"status": "cleared"})

    # Sanitize and validate the file exists
    file_id = _safe_name(file_id)
    if not file_id:
        return jsonify({"error": "Invalid file ID"}), 400
    d = _opcode_files_dir(addon_id)
    path = os.path.join(d, f"{file_id}.json")
    if not os.path.isfile(path):
        return jsonify({"error": "File not found"}), 404

    if addon_id == "eq_session":
        try:
            from addons.eq_session.opcodes import set_active_opcodes
            set_active_opcodes(file_id)
        except ImportError:
            pass

    return jsonify({"status": "ok", "file_id": file_id})


@bp.route("/api/opcode-files/<addon_id>/save", methods=["POST"])
def opcode_files_save(addon_id):
    """Save opcodes as a new opcode file.

    Body: {"name": "MyClient", "opcodes": {"0x1234": "OP_Name", ...}}
    If opcodes is omitted, saves the current discovery session labels.
    """
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Name is required"}), 400

    safe_name = _safe_name(name)
    if not safe_name:
        return jsonify({"error": "Invalid name"}), 400

    opcodes = data.get("opcodes")
    if opcodes is None and _discovery_session is not None:
        # Use current discovery session labels
        opcodes = {f"0x{k:04x}": v for k, v in _discovery_session.labels.items()}

    if not opcodes:
        return jsonify({"error": "No opcodes to save"}), 400

    d = _opcode_files_dir(addon_id)
    path = os.path.join(d, f"{safe_name}.json")
    with open(path, "w") as f:
        json.dump(opcodes, f, indent=2, sort_keys=True)

    return jsonify({"status": "ok", "file_id": safe_name, "count": len(opcodes)})


# ---------------------------------------------------------------------------
# Discovery tab API
# ---------------------------------------------------------------------------

# Module-level discovery session (one at a time)
_discovery_session = None


@bp.route("/api/discovery/addons")
def discovery_addons():
    """List addons that support the Discovery tab."""
    from ..addon_loader import get_discovery_addons
    return jsonify(get_discovery_addons())


@bp.route("/api/discovery/start", methods=["POST"])
def discovery_start():
    """Start a discovery session with an optional addon."""
    global _discovery_session
    from ..discovery import DiscoverySession, load_labels

    data = request.get_json(silent=True) or {}
    addon_id = data.get("addon_id")  # None = raw mode

    _discovery_session = DiscoverySession(addon_id=addon_id)

    # Load persisted labels if they exist
    labels_path = _discovery_labels_path(addon_id)
    if labels_path:
        _discovery_session.labels = load_labels(labels_path)

    return jsonify({"status": "started", "addon_id": addon_id})


@bp.route("/api/discovery/stop", methods=["POST"])
def discovery_stop():
    """Stop the current discovery session."""
    global _discovery_session
    from ..discovery import save_labels

    if _discovery_session is not None:
        # Persist labels before clearing
        labels_path = _discovery_labels_path(_discovery_session.addon_id)
        if labels_path and _discovery_session.labels:
            save_labels(_discovery_session.labels, labels_path)
        _discovery_session.active = False
        _discovery_session = None
    return jsonify({"status": "stopped"})


@bp.route("/api/discovery/status")
def discovery_status():
    """Return current discovery session state."""
    if _discovery_session is None:
        return jsonify({"active": False})
    return jsonify({
        "active": _discovery_session.active,
        "addon_id": _discovery_session.addon_id,
        "opcode_count": len(_discovery_session.opcode_groups),
        "has_baseline": _discovery_session.baseline is not None,
    })


@bp.route("/api/discovery/opcodes")
def discovery_opcodes():
    """Return all opcode groups with counts, sizes, and auto-tags."""
    if _discovery_session is None:
        return jsonify([])

    # Build known_opcodes from the active opcode file + discovery hooks
    known_opcodes = {}
    if _discovery_session.addon_id:
        # Get app-layer opcodes from the active opcode file (eq_session only for now)
        if _discovery_session.addon_id == "eq_session":
            try:
                from addons.eq_session.opcodes import get_active_opcodes
                known_opcodes.update(get_active_opcodes())
            except ImportError:
                pass
        # Overlay session-layer opcodes from discovery hooks
        from ..addon_loader import get_addon_discovery_hooks
        hooks = get_addon_discovery_hooks(_discovery_session.addon_id)
        if hooks and hooks.get("known_opcodes"):
            known_opcodes.update(hooks["known_opcodes"])

    return jsonify(_discovery_session.get_opcodes(known_opcodes=known_opcodes or None))


@bp.route("/api/discovery/opcodes/<int:opcode>/fields")
def discovery_opcode_fields(opcode):
    """Run field analysis on a specific opcode group."""
    from ..discovery import analyze_fields

    if _discovery_session is None:
        return jsonify({"error": "No active session"}), 400

    group = _discovery_session.get_group(opcode)
    if group is None:
        return jsonify({"error": "Opcode not found"}), 404

    fields = analyze_fields(group)
    return jsonify({
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04x}",
        "sample_count": len(group.samples),
        "total_count": group.count,
        "size": group.size_display,
        "label": _discovery_session.labels.get(opcode, ""),
        "fields": fields,
    })


@bp.route("/api/discovery/opcodes/<int:opcode>/label", methods=["PUT"])
def discovery_set_label(opcode):
    """Set a user label for an opcode."""
    from ..discovery import save_labels

    if _discovery_session is None:
        return jsonify({"error": "No active session"}), 400

    data = request.get_json(silent=True) or {}
    label = data.get("label", "").strip()
    _discovery_session.set_label(opcode, label)

    # Auto-save labels
    labels_path = _discovery_labels_path(_discovery_session.addon_id)
    if labels_path:
        save_labels(_discovery_session.labels, labels_path)

    return jsonify({"status": "ok", "opcode": opcode, "label": label})


@bp.route("/api/discovery/baseline/start", methods=["POST"])
def discovery_baseline_start():
    """Snapshot current opcode counts as baseline."""
    if _discovery_session is None:
        return jsonify({"error": "No active session"}), 400
    _discovery_session.start_baseline()
    return jsonify({"status": "baseline_started"})


@bp.route("/api/discovery/baseline/diff")
def discovery_baseline_diff():
    """Return diff between current state and baseline."""
    if _discovery_session is None:
        return jsonify({"error": "No active session"}), 400
    return jsonify(_discovery_session.compute_diff())


@bp.route("/api/discovery/baseline/clear", methods=["POST"])
def discovery_baseline_clear():
    """Clear the baseline."""
    if _discovery_session is None:
        return jsonify({"error": "No active session"}), 400
    _discovery_session.clear_baseline()
    return jsonify({"status": "baseline_cleared"})


@bp.route("/api/discovery/labels")
def discovery_labels():
    """Return all saved labels for the current session."""
    if _discovery_session is None:
        return jsonify({})
    return jsonify({f"0x{k:04x}": v for k, v in _discovery_session.labels.items()})


def _discovery_labels_path(addon_id):
    """Return the file path for persisting discovery labels.

    Labels are stored in the unified opcode_files/ folder as
    _discovery_labels.json under the addon's subfolder.
    """
    d = _opcode_files_dir(addon_id)
    return os.path.join(d, "_discovery_labels.json")


def get_discovery_session():
    """Return the active discovery session (used by addon_loader)."""
    return _discovery_session


@bp.route("/api/shutdown", methods=["POST"])
def shutdown():
    """Stop capture, clean up, and terminate the server."""
    engine = current_app.config["capture_engine"]
    mapper = current_app.config["process_mapper"]
    if engine.is_running:
        engine.stop()
        mapper.stop()
    # Kill the server process
    os.kill(os.getpid(), signal.SIGTERM)
