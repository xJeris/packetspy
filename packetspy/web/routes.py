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
    from ..addon_loader import reset_flow_tracker, run_addons

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
    """Return active TCP streams."""
    engine = current_app.config["capture_engine"]
    sort_by = request.args.get("sort", "last_seen")
    limit = int(request.args.get("limit", 100))
    return jsonify(engine.stream_tracker.get_streams(limit=limit, sort_by=sort_by))


@bp.route("/api/streams/<int:stream_id>/packets")
def get_stream_packets(stream_id):
    """Return packets for a specific TCP stream."""
    engine = current_app.config["capture_engine"]
    packet_nums = set(engine.stream_tracker.get_stream_packets(stream_id))
    packets = [p for p in engine.packet_buffer if p and p.get("num") in packet_nums]
    return jsonify(packets)


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
