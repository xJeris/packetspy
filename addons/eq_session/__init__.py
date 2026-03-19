"""EQ Session Protocol addon for PacketSpy.

Parses the EverQuest (SOE) session protocol layer from raw UDP payloads.
Identifies session opcodes, sequence numbers, CRC stripping, decompression,
and application-layer opcode labeling using RoF2 opcode mappings.

This is a stateful addon. It uses flow_ctx.store["eq_session"] (preferred)
or the legacy init()/SessionState mechanism to track CRC byte count and
encode key from OP_SessionResponse handshakes across packets in the same flow.
"""

import struct

from .session_state import SessionState
from .crc import strip_crc
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

    # Determine CRC byte count from flow context or legacy session state
    session = None
    if flow_ctx is not None:
        session = flow_ctx.store.get("eq_session")
    if session is None and state is not None:
        session = state.get(packet_info)
    crc_bytes = session["crc_bytes"] if session else 2

    # Strip CRC from data-carrying opcodes before further parsing
    data = payload_bytes
    if opcode_byte in _DATA_OPCODES:
        data = strip_crc(payload_bytes, crc_bytes)
        if len(data) < len(payload_bytes):
            fields.append({"name": "CRC stripped", "value": f"{crc_bytes} bytes"})

    # Per-opcode parsing
    if opcode_byte == 0x01:
        _parse_session_request(data, fields)
        notes = _notes_session_request(data)
    elif opcode_byte == 0x02:
        _parse_session_response(data, fields, packet_info, state, flow_ctx)
        notes = _notes_session_response(data)
    elif opcode_byte == 0x03:
        count = _parse_combined(data, fields)
        notes = f"OP_Combined ({count} sub-packets)"
    elif opcode_byte == 0x09:
        notes = _parse_packet(data, fields)
    elif opcode_byte == 0x0d:
        notes = _parse_fragment(data, fields)
    elif opcode_byte == 0x15 or opcode_byte == 0x11:
        notes = _parse_ack(data, fields, opcode_name)
    elif opcode_byte == 0x19:
        count = _parse_combined(data, fields)
        notes = f"OP_AppCombined ({count} sub-packets)"
    else:
        fields.append({"name": "Payload length", "value": f"{len(data) - 2} bytes"})

    return {"fields": fields, "notes": notes}


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
    session_data = {"crc_bytes": crc_byte_count, "encode_key": encode_key}
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


def _parse_combined(payload, fields):
    count = 0
    offset = 2
    data_len = len(payload)
    while offset < data_len:
        if offset >= data_len:
            break
        sub_len = payload[offset]
        offset += 1 + sub_len
        count += 1
    fields.append({"name": "Sub-packets", "value": str(count)})
    fields.append({"name": "Payload length", "value": f"{len(payload) - 2} bytes"})
    return count


def _parse_packet(payload, fields):
    """Parse OP_Packet: sequence + decompress + app opcode labeling."""
    if len(payload) < 4:
        fields.append({"name": "Payload length", "value": f"{len(payload) - 2} bytes"})
        return "OP_Packet"

    seq = struct.unpack_from(">H", payload, 2)[0]
    fields.append({"name": "Sequence", "value": str(seq)})

    # Application data starts after [0x00, opcode, seq_hi, seq_lo]
    app_data = payload[4:]
    if not app_data:
        fields.append({"name": "Payload length", "value": "0 bytes"})
        return f"OP_Packet seq={seq}"

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
    return f"OP_Packet seq={seq}{comp_note}{opcode_note}"


def _parse_fragment(payload, fields):
    if len(payload) < 4:
        return "OP_Fragment"
    seq = struct.unpack_from(">H", payload, 2)[0]
    fields.append({"name": "Sequence", "value": str(seq)})

    if len(payload) >= 8:
        possible_total = struct.unpack_from(">I", payload, 4)[0]
        if possible_total > len(payload) and possible_total < 1_000_000:
            fields.append({"name": "Fragment", "value": f"First (total {possible_total} bytes)"})
            fields.append({"name": "Payload offset", "value": "8 bytes"})
            fields.append({"name": "Payload length", "value": f"{len(payload) - 8} bytes"})
            return f"OP_Fragment seq={seq} total={possible_total}B (first)"
        else:
            fields.append({"name": "Fragment", "value": "Continuation"})
            fields.append({"name": "Payload offset", "value": "4 bytes"})
            fields.append({"name": "Payload length", "value": f"{len(payload) - 4} bytes"})
            return f"OP_Fragment seq={seq} (continuation)"

    fields.append({"name": "Payload offset", "value": "4 bytes"})
    fields.append({"name": "Payload length", "value": f"{len(payload) - 4} bytes"})
    return f"OP_Fragment seq={seq}"


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
