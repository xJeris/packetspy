"""EQ Session Protocol addon for PacketSpy.

Parses the EverQuest (SOE) session protocol layer from raw UDP payloads.
Identifies session opcodes, sequence numbers, CRC stripping, decompression,
and application-layer opcode labeling using RoF2 opcode mappings.

This is a stateful addon. It uses flow_ctx.store["eq_session"] (preferred)
or the legacy init()/SessionState mechanism to track CRC byte count and
encode key from OP_SessionResponse handshakes across packets in the same flow.
"""

import struct

from .session_state import (
    SessionState, frag_start, frag_append, frag_is_complete,
    frag_pop_complete, frag_save_result, frag_lookup_result,
)
from .crc import strip_crc
from .decode import decode_payload
from .decompress import decompress_payload
from .opcodes import lookup as lookup_opcode

ADDON_INFO = {
    "name": "EQ Session Protocol",
    "protocol": "udp",
}

# SOE session protocol opcodes (byte[1] when byte[0] == 0x00)
SESSION_OPCODES = {
    0x01: "OP_SessionRequest",
    0x02: "OP_SessionResponse",
    0x03: "OP_Combined",
    0x05: "OP_SessionDisconnect",
    0x06: "OP_KeepAlive",
    0x07: "OP_SessionStatRequest",
    0x08: "OP_SessionStatResponse",
    0x09: "OP_Packet",
    0x0d: "OP_Fragment",
    0x11: "OP_OutOfOrderAck",
    0x15: "OP_Ack",
    0x19: "OP_AppCombined",
    0x1d: "OP_OutOfSession",
}

# Session opcodes that carry application data (need CRC strip + decompress)
_DATA_OPCODES = {0x09, 0x0d, 0x03, 0x19}


def init():
    """Return a new SessionState for per-flow tracking."""
    return SessionState()


def parse(payload_bytes, packet_info, state=None, flow_ctx=None):
    """Parse EQ session protocol header from raw UDP payload bytes.

    Returns a dict with fields and notes, or None if not applicable.
    """
    if not payload_bytes or len(payload_bytes) < 2:
        return None

    # Non-zero byte[0] means raw application data (no session wrapper)
    if payload_bytes[0] != 0x00:
        return {
            "fields": [
                {"name": "Type", "value": "Raw App Data"},
                {"name": "First byte", "value": f"0x{payload_bytes[0]:02x}"},
                {"name": "Payload length", "value": f"{len(payload_bytes)} bytes"},
            ],
            "notes": "Raw application data (no session wrapper)",
        }

    opcode_byte = payload_bytes[1]
    if opcode_byte not in SESSION_OPCODES:
        return None

    opcode_name = SESSION_OPCODES[opcode_byte]
    fields = [{"name": "Opcode", "value": f"{opcode_name} (0x{opcode_byte:02x})"}]
    notes = opcode_name

    # Determine CRC byte count and encode params from flow context or legacy state
    session = None
    if flow_ctx is not None:
        session = flow_ctx.store.get("eq_session")
    if session is None and state is not None:
        session = state.get(packet_info)
    crc_bytes = session["crc_bytes"] if session else 2
    encode_key = session.get("encode_key", 0) if session else 0
    encode_pass1 = session.get("encode_pass1", 0) if session else 0
    encode_pass2 = session.get("encode_pass2", 0) if session else 0

    # Strip CRC from data-carrying opcodes, then XOR decode before further parsing
    data = payload_bytes
    flags = []
    if opcode_byte in _DATA_OPCODES:
        data = strip_crc(payload_bytes, crc_bytes)
        if len(data) < len(payload_bytes):
            fields.append({"name": "CRC stripped", "value": f"{crc_bytes} bytes"})
        # XOR decode (must happen after CRC strip, before decompression)
        data, was_decoded = decode_payload(data, encode_key, encode_pass1, encode_pass2)
        if was_decoded:
            fields.append({"name": "XOR decoded", "value": f"key=0x{encode_key:08x}"})
            flags.append("decrypted")

    # Per-opcode parsing — decoded_bytes collects processed app-layer payload
    decoded_bytes = None
    if opcode_byte == 0x01:
        _parse_session_request(data, fields)
        notes = _notes_session_request(data)
    elif opcode_byte == 0x02:
        _parse_session_response(data, fields, packet_info, state, flow_ctx)
        notes = _notes_session_response(data)
    elif opcode_byte == 0x03:
        count = _parse_combined(data, fields, flow_ctx)
        notes = f"OP_Combined ({count} sub-packets)"
    elif opcode_byte == 0x09:
        notes, decoded_bytes = _parse_packet(data, fields)
    elif opcode_byte == 0x0d:
        notes, decoded_bytes = _parse_fragment(data, fields, flow_ctx)
    elif opcode_byte == 0x15 or opcode_byte == 0x11:
        notes = _parse_ack(data, fields, opcode_name)
    elif opcode_byte == 0x19:
        count = _parse_combined(data, fields, flow_ctx)
        notes = f"OP_AppCombined ({count} sub-packets)"
    else:
        fields.append({"name": "Payload length", "value": f"{len(data) - 2} bytes"})

    result = {"fields": fields, "notes": notes}
    if flags:
        result["flags"] = flags
    if decoded_bytes and len(decoded_bytes) > 0:
        result["decoded_payload"] = decoded_bytes.hex()
    # Include byte region map for raw hex annotation
    if opcode_byte in _DATA_OPCODES:
        result["byte_regions"] = _build_byte_regions(payload_bytes, crc_bytes, opcode_byte)
    return result


def _parse_session_request(payload, fields):
    if len(payload) < 10:
        return
    proto_ver = struct.unpack_from(">I", payload, 2)[0]
    session_id = struct.unpack_from(">I", payload, 6)[0]
    fields.append({"name": "Protocol version", "value": str(proto_ver)})
    fields.append({"name": "Session ID", "value": f"0x{session_id:08x}"})


def _notes_session_request(payload):
    if len(payload) < 10:
        return "OP_SessionRequest"
    proto_ver = struct.unpack_from(">I", payload, 2)[0]
    session_id = struct.unpack_from(">I", payload, 6)[0]
    return f"OP_SessionRequest proto={proto_ver} session=0x{session_id:08x}"


def _parse_session_response(payload, fields, packet_info, state, flow_ctx=None):
    if len(payload) < 17:
        return
    session_id = struct.unpack_from(">I", payload, 2)[0]
    crc_byte_count = payload[6]
    encode_pass1 = payload[7]
    encode_pass2 = payload[8]
    encode_key = struct.unpack_from(">I", payload, 9)[0]
    max_pkt = struct.unpack_from(">I", payload, 13)[0]
    fields.append({"name": "Session ID", "value": f"0x{session_id:08x}"})
    fields.append({"name": "CRC bytes", "value": str(crc_byte_count)})
    fields.append({"name": "Encode pass 1", "value": str(encode_pass1)})
    fields.append({"name": "Encode pass 2", "value": str(encode_pass2)})
    fields.append({"name": "Encode key", "value": f"0x{encode_key:08x}"})
    fields.append({"name": "Max packet size", "value": str(max_pkt)})

    # Store session params for future packets in this flow
    session_data = {
        "crc_bytes": crc_byte_count,
        "encode_key": encode_key,
        "encode_pass1": encode_pass1,
        "encode_pass2": encode_pass2,
    }
    if flow_ctx is not None:
        flow_ctx.store["eq_session"] = session_data
    if state:
        state.update(packet_info, crc_byte_count, encode_key)


def _notes_session_response(payload):
    if len(payload) < 17:
        return "OP_SessionResponse"
    session_id = struct.unpack_from(">I", payload, 2)[0]
    crc_bytes = payload[6]
    encode_key = struct.unpack_from(">I", payload, 9)[0]
    max_pkt = struct.unpack_from(">I", payload, 13)[0]
    return (
        f"OP_SessionResponse session=0x{session_id:08x} "
        f"crc={crc_bytes}B key=0x{encode_key:08x} max={max_pkt}"
    )


def _parse_combined(payload, fields, flow_ctx=None):
    count = 0
    offset = 2
    data_len = len(payload)
    while offset < data_len:
        sub_len = payload[offset]
        offset += 1
        if offset + sub_len > data_len:
            break
        sub_data = payload[offset:offset + sub_len]
        offset += sub_len
        count += 1
        _parse_sub_packet(sub_data, fields, count, flow_ctx)
    fields.append({"name": "Sub-packets", "value": str(count)})
    fields.append({"name": "Payload length", "value": f"{len(payload) - 2} bytes"})
    return count


def _parse_sub_packet(data, fields, index, flow_ctx=None):
    """Parse a single sub-packet from OP_Combined and append fields."""
    if len(data) < 2:
        fields.append({"name": f"Sub {index}", "value": f"{len(data)} bytes (too short)"})
        return

    # Sub-packets starting with 0x00 are session-layer messages
    if data[0] == 0x00:
        opcode_byte = data[1]
        opcode_name = SESSION_OPCODES.get(opcode_byte)
        if opcode_name:
            sub_fields = []
            if opcode_byte == 0x09:
                note, _ = _parse_packet(data, sub_fields)
            elif opcode_byte == 0x0d:
                note, _ = _parse_fragment(data, sub_fields, flow_ctx)
            elif opcode_byte in (0x15, 0x11):
                note = _parse_ack(data, sub_fields, opcode_name)
            else:
                note = f"{opcode_name} ({len(data)} bytes)"
            fields.append({"name": f"Sub {index}", "value": note})
            for f in sub_fields:
                fields.append({"name": f"  {f['name']}", "value": f["value"]})
            return

    # Non-session sub-packet: likely raw app data with 2-byte LE opcode
    sub_fields = []
    app_opcode_str = _read_app_opcode(data, sub_fields)
    if app_opcode_str:
        fields.append({"name": f"Sub {index}", "value": f"App: {app_opcode_str} ({len(data)} bytes)"})
    else:
        fields.append({"name": f"Sub {index}", "value": f"0x{data[0]:02x}... ({len(data)} bytes)"})


def _parse_packet(payload, fields):
    """Parse OP_Packet: sequence + decompress + app opcode labeling.

    Returns (notes_str, decoded_bytes_or_None).
    """
    if len(payload) < 4:
        fields.append({"name": "Payload length", "value": f"{len(payload) - 2} bytes"})
        return "OP_Packet", None

    seq = struct.unpack_from(">H", payload, 2)[0]
    fields.append({"name": "Sequence", "value": str(seq)})

    # Application data starts after [0x00, opcode, seq_hi, seq_lo]
    app_data = payload[4:]
    if not app_data:
        fields.append({"name": "Payload length", "value": "0 bytes"})
        return f"OP_Packet seq={seq}", None

    # Decompress if needed
    decompressed, was_compressed = decompress_payload(app_data)

    if was_compressed:
        fields.append({
            "name": "Decompressed",
            "value": f"yes ({len(app_data) - 1} → {len(decompressed)} bytes)",
        })
    else:
        flag = app_data[0]
        if flag == 0xa5:
            fields.append({"name": "Compression", "value": "0xa5 (uncompressed)"})
        elif flag == 0x5a:
            # Decompression was attempted but failed
            fields.append({"name": "Compression", "value": "0x5a (decompress failed)"})

    # Try to read 2-byte little-endian app opcode from decompressed data
    app_opcode_str = _read_app_opcode(decompressed, fields)

    fields.append({"name": "Payload length", "value": f"{len(decompressed)} bytes"})

    comp_note = ", compressed" if was_compressed else ""
    opcode_note = f" {app_opcode_str}" if app_opcode_str else ""
    return f"OP_Packet seq={seq}{comp_note}{opcode_note}", decompressed


def _parse_fragment(payload, fields, flow_ctx=None):
    """Parse OP_Fragment with stateful reassembly via flow_ctx.

    Returns (notes_str, decoded_bytes_or_None).
    """
    if len(payload) < 4:
        return "OP_Fragment", None
    seq = struct.unpack_from(">H", payload, 2)[0]
    fields.append({"name": "Sequence", "value": str(seq)})

    store = flow_ctx.store if flow_ctx is not None else None

    # Check for a cached reassembly result from a prior processing pass
    if store is not None:
        cached = frag_lookup_result(store, seq)
        if cached:
            return _show_cached_reassembly(cached, fields, seq), None

    # Detect first fragment: has 4-byte total_size field after sequence
    if len(payload) >= 8:
        possible_total = struct.unpack_from(">I", payload, 4)[0]
        if possible_total > len(payload) and possible_total < 1_000_000:
            frag_data = payload[8:]  # skip [0x00, opcode, seq_hi, seq_lo, total_size(4)]
            fields.append({"name": "Fragment", "value": f"First (total {possible_total} bytes)"})
            fields.append({"name": "Payload length", "value": f"{len(frag_data)} bytes"})

            # Start reassembly buffer
            if store is not None:
                frag_start(store, seq, possible_total, frag_data)

            return f"OP_Fragment seq={seq} total={possible_total}B (first)", None

    # Continuation fragment
    frag_data = payload[4:]  # skip [0x00, opcode, seq_hi, seq_lo]

    if store is not None:
        buf = frag_append(store, frag_data)
        if buf is not None:
            est_total_frags = max(1, -(-buf["total_size"] // max(1, buf["accumulated"] // buf["chunk_count"])))
            fields.append({
                "name": "Fragment",
                "value": f"{buf['chunk_count']}/{est_total_frags}, {buf['accumulated']}/{buf['total_size']} bytes",
            })

            # Check if reassembly is complete
            if frag_is_complete(store):
                reassembled, buf_info = frag_pop_complete(store)
                if reassembled:
                    return _finish_reassembly(reassembled, fields, seq, buf_info, store)

            fields.append({"name": "Payload length", "value": f"{len(frag_data)} bytes"})
            return f"OP_Fragment seq={seq} ({buf['chunk_count']}/{est_total_frags})", None

    # No flow context or no active buffer — basic display
    fields.append({"name": "Fragment", "value": "Continuation"})
    fields.append({"name": "Payload length", "value": f"{len(frag_data)} bytes"})
    return f"OP_Fragment seq={seq} (continuation)", None


def _finish_reassembly(reassembled, fields, seq, buf_info, store=None):
    """Handle completed fragment reassembly: decompress + app opcode lookup.

    Returns (notes_str, decoded_bytes).
    """
    fields.append({
        "name": "Reassembled",
        "value": f"{buf_info['total_size']} bytes from {buf_info['chunk_count']} fragments",
    })

    # Decompress the reassembled payload
    decompressed, was_compressed = decompress_payload(reassembled)

    if was_compressed:
        fields.append({
            "name": "Decompressed",
            "value": f"yes ({len(reassembled) - 1} \u2192 {len(decompressed)} bytes)",
        })

    # Read app opcode from reassembled + decompressed data
    app_opcode_str = _read_app_opcode(decompressed, fields)

    fields.append({"name": "Payload length", "value": f"{len(decompressed)} bytes"})

    # Cache the result so any fragment in this group can display it later
    if store is not None:
        frag_save_result(store, buf_info["first_seq"], seq, {
            "app_opcode": app_opcode_str,
            "total_size": buf_info["total_size"],
            "chunk_count": buf_info["chunk_count"],
            "decompressed_size": len(decompressed),
            "was_compressed": was_compressed,
        })

    comp_note = ", compressed" if was_compressed else ""
    opcode_note = f" \u2192 {app_opcode_str}" if app_opcode_str else ""
    return f"OP_Fragment seq={seq} (complete{comp_note}{opcode_note})", decompressed


def _show_cached_reassembly(cached, fields, seq):
    """Display reassembly result from cache for any fragment in a completed group."""
    app_opcode = cached.get("app_opcode", "?")
    total_size = cached.get("total_size", 0)
    chunk_count = cached.get("chunk_count", 0)
    decompressed_size = cached.get("decompressed_size", 0)
    was_compressed = cached.get("was_compressed", False)
    first_seq = cached.get("first_seq", "?")
    last_seq = cached.get("last_seq", "?")

    fields.append({
        "name": "Reassembled",
        "value": f"{total_size} bytes from {chunk_count} fragments (seq {first_seq}\u2013{last_seq})",
    })
    if was_compressed:
        fields.append({
            "name": "Decompressed",
            "value": f"yes \u2192 {decompressed_size} bytes",
        })
    if app_opcode:
        fields.append({"name": "App opcode", "value": app_opcode})

    comp_note = ", compressed" if was_compressed else ""
    opcode_note = f" \u2192 {app_opcode}" if app_opcode else ""
    return f"OP_Fragment seq={seq} (reassembled{comp_note}{opcode_note})"


def _parse_ack(payload, fields, opcode_name):
    if len(payload) < 4:
        return opcode_name
    ack_seq = struct.unpack_from(">H", payload, 2)[0]
    fields.append({"name": "Sequence", "value": str(ack_seq)})
    return f"{opcode_name} seq={ack_seq}"


def _read_app_opcode(data, fields):
    """Read 2-byte LE app opcode from decompressed data, look up name."""
    if len(data) < 2:
        return None

    opcode_val = struct.unpack_from("<H", data, 0)[0]
    opcode_name = lookup_opcode(opcode_val)

    if opcode_name:
        fields.append({
            "name": "App opcode",
            "value": f"{opcode_name} (0x{opcode_val:04x})",
        })
        return opcode_name
    else:
        fields.append({
            "name": "App opcode",
            "value": f"0x{opcode_val:04x}",
        })
        return f"0x{opcode_val:04x}"


def _build_byte_regions(raw_payload, crc_bytes, opcode_byte):
    """Build a byte-region map for color-coding the raw hex dump.

    Returns a list of {"start": int, "end": int, "type": str} dicts
    describing contiguous byte regions in the raw UDP payload.
    """
    total = len(raw_payload)
    regions = []

    # Bytes 0-1: session opcode header (always present)
    regions.append({"start": 0, "end": 2, "type": "header"})

    if opcode_byte in (0x09, 0x0d):
        # OP_Packet / OP_Fragment: bytes 2-3 = sequence
        regions.append({"start": 2, "end": 4, "type": "sequence"})
        if opcode_byte == 0x0d and total >= 8:
            # OP_Fragment first: bytes 4-7 = total_size
            possible_total = struct.unpack_from(">I", raw_payload, 4)[0]
            if possible_total > total and possible_total < 1_000_000:
                regions.append({"start": 4, "end": 8, "type": "frag-size"})
                payload_start = 8
            else:
                payload_start = 4
        else:
            payload_start = 4
        # Payload region (excluding trailing CRC)
        payload_end = total - crc_bytes if crc_bytes and total > crc_bytes else total
        if payload_start < payload_end:
            regions.append({"start": payload_start, "end": payload_end, "type": "payload"})
        # CRC region
        if crc_bytes and payload_end < total:
            regions.append({"start": payload_end, "end": total, "type": "crc"})
    elif opcode_byte in (0x03, 0x19):
        # OP_Combined / OP_AppCombined: all after header is sub-packets + CRC
        payload_end = total - crc_bytes if crc_bytes and total > crc_bytes else total
        if 2 < payload_end:
            regions.append({"start": 2, "end": payload_end, "type": "payload"})
        if crc_bytes and payload_end < total:
            regions.append({"start": payload_end, "end": total, "type": "crc"})

    return regions
