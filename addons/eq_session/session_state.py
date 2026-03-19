"""Per-flow session state tracking for EQ addon.

Stores CRC byte count and encode key learned from OP_SessionResponse
so subsequent packets in the same session can be properly parsed.

Also provides fragment reassembly helpers that operate on a buffer dict
stored in flow_ctx.store["eq_fragments"].
"""

import time

# Maximum reassembled payload size (512 KB safety cap)
_MAX_REASSEMBLY_SIZE = 512 * 1024

# Stale fragment buffer age in seconds
_FRAGMENT_TTL = 30


class SessionState:
    def __init__(self):
        # (ip_a, ip_b) -> {"crc_bytes": int, "encode_key": int}
        self.sessions = {}

    def update(self, packet_info, crc_bytes, encode_key):
        """Store session parameters from OP_SessionResponse."""
        key = self._flow_key(packet_info)
        self.sessions[key] = {
            "crc_bytes": crc_bytes,
            "encode_key": encode_key,
        }

    def get(self, packet_info):
        """Get session parameters for this flow, or None."""
        return self.sessions.get(self._flow_key(packet_info))

    def _flow_key(self, pinfo):
        """Normalize IP pair so both directions map to same session."""
        src = pinfo.get("src_ip") or ""
        dst = pinfo.get("dst_ip") or ""
        return tuple(sorted([src, dst]))


# --- Fragment reassembly helpers ---
# These operate on a plain dict stored in flow_ctx.store["eq_fragments"].
# Buffer format: {"total_size": int, "chunks": [bytes], "accumulated": int,
#                 "first_seq": int, "chunk_count": int, "started": float}
# or None if no active reassembly.


def frag_start(store, seq, total_size, first_data):
    """Initialize a fragment reassembly buffer for a first-fragment packet.

    Returns the buffer dict for field display purposes.
    """
    if total_size > _MAX_REASSEMBLY_SIZE:
        return None

    # Evict any stale prior buffer
    _frag_cleanup(store)

    buf = {
        "total_size": total_size,
        "chunks": [first_data],
        "accumulated": len(first_data),
        "first_seq": seq,
        "chunk_count": 1,
        "started": time.time(),
    }
    store["eq_fragments"] = buf
    return buf


def frag_append(store, data):
    """Append continuation fragment data to the active buffer.

    Returns the buffer dict, or None if no active buffer.
    """
    buf = store.get("eq_fragments")
    if buf is None:
        return None

    # Check TTL
    if time.time() - buf["started"] > _FRAGMENT_TTL:
        store.pop("eq_fragments", None)
        return None

    buf["chunks"].append(data)
    buf["accumulated"] += len(data)
    buf["chunk_count"] += 1
    return buf


def frag_is_complete(store):
    """Check if the active fragment buffer has enough data."""
    buf = store.get("eq_fragments")
    if buf is None:
        return False
    return buf["accumulated"] >= buf["total_size"]


def frag_pop_complete(store):
    """Return (reassembled_bytes, buf_info) and clear the buffer.

    Returns (None, None) if incomplete. buf_info is a snapshot of the
    buffer metadata at completion time.
    """
    buf = store.get("eq_fragments")
    if buf is None or buf["accumulated"] < buf["total_size"]:
        return None, None

    reassembled = b"".join(buf["chunks"])
    # Trim to total_size (last fragment may have trailing CRC bytes already stripped)
    reassembled = reassembled[:buf["total_size"]]

    # Snapshot metadata before clearing
    buf_info = {
        "total_size": buf["total_size"],
        "chunk_count": buf["chunk_count"],
        "first_seq": buf["first_seq"],
    }
    store.pop("eq_fragments", None)
    return reassembled, buf_info


def frag_save_result(store, first_seq, last_seq, result):
    """Cache a reassembly result so detail-view clicks can retrieve it.

    Keyed by sequence number range so any fragment in the group can look it up.
    """
    if "eq_reassembled" not in store:
        store["eq_reassembled"] = {}
    entry = {**result, "first_seq": first_seq, "last_seq": last_seq}
    store["eq_reassembled"][first_seq] = entry
    store["eq_reassembled"][last_seq] = entry


def frag_lookup_result(store, seq):
    """Look up a cached reassembly result that covers the given sequence number."""
    cache = store.get("eq_reassembled")
    if not cache:
        return None
    # Direct hit (first or last seq)
    if seq in cache:
        return cache[seq]
    # Range scan for sequences between first and last
    seen = set()
    for entry in cache.values():
        eid = id(entry)
        if eid in seen:
            continue
        seen.add(eid)
        if entry["first_seq"] <= seq <= entry["last_seq"]:
            return entry
    return None


def frag_get(store):
    """Return the current fragment buffer, or None."""
    return store.get("eq_fragments")


def _frag_cleanup(store):
    """Remove stale fragment buffer if it's too old."""
    buf = store.get("eq_fragments")
    if buf and time.time() - buf["started"] > _FRAGMENT_TTL:
        store.pop("eq_fragments", None)
