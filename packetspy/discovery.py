"""Protocol discovery engine for PacketSpy.

Provides opcode grouping, structural field analysis, heuristic type
detection, and baseline diffing for unknown protocol reverse engineering.
"""

import json
import math
import os
import struct
import threading
import time
from collections import deque


# Maximum decoded payload samples to keep per opcode group
MAX_SAMPLES = 100


class OpcodeGroup:
    """Accumulates payload samples for a single 2-byte opcode value."""

    __slots__ = ("opcode", "samples", "count", "first_seen", "last_seen",
                 "sizes_seen", "rate_window")

    def __init__(self, opcode, timestamp):
        self.opcode = opcode
        self.samples = deque(maxlen=MAX_SAMPLES)
        self.count = 0
        self.first_seen = timestamp
        self.last_seen = timestamp
        # Track distinct payload sizes to determine fixed vs variable
        self.sizes_seen = set()
        # Sliding window for rate estimation (last 60 timestamps)
        self.rate_window = deque(maxlen=60)

    def add(self, payload, timestamp):
        """Add a decoded payload sample (bytes after the 2-byte opcode)."""
        self.samples.append(payload)
        self.count += 1
        self.last_seen = timestamp
        self.sizes_seen.add(len(payload))
        self.rate_window.append(timestamp)

    @property
    def size_fixed(self):
        return len(self.sizes_seen) == 1

    @property
    def size_display(self):
        if self.size_fixed and self.sizes_seen:
            return next(iter(self.sizes_seen))
        return "var"

    @property
    def rate_per_sec(self):
        """Estimated packets/sec over the rate window."""
        if len(self.rate_window) < 2:
            return 0.0
        span = self.rate_window[-1] - self.rate_window[0]
        if span <= 0:
            return 0.0
        return (len(self.rate_window) - 1) / span

    def summary(self, auto_tags=None):
        """Return a JSON-serializable summary dict."""
        return {
            "opcode": self.opcode,
            "opcode_hex": f"0x{self.opcode:04x}",
            "count": self.count,
            "size": self.size_display,
            "size_fixed": self.size_fixed,
            "rate": round(self.rate_per_sec, 1),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "sample_count": len(self.samples),
            "auto_tags": auto_tags or [],
        }


class DiscoverySession:
    """Manages one discovery session — accumulates and analyzes packets."""

    def __init__(self, addon_id=None):
        self.addon_id = addon_id
        self.opcode_groups = {}   # int opcode -> OpcodeGroup
        self.baseline = None      # dict[int, int] snapshot or None
        self.labels = {}          # int opcode -> str label
        self.active = True
        self._lock = threading.Lock()

    def ingest(self, clean_payload, timestamp):
        """Ingest a decoded payload. Extracts 2-byte LE opcode and stores the rest.

        clean_payload: bytes — full decoded application-layer data (opcode + body).
        """
        if not clean_payload or len(clean_payload) < 2:
            return

        opcode = struct.unpack_from("<H", clean_payload, 0)[0]
        body = clean_payload[2:]

        with self._lock:
            group = self.opcode_groups.get(opcode)
            if group is None:
                group = OpcodeGroup(opcode, timestamp)
                self.opcode_groups[opcode] = group
            group.add(body, timestamp)

    def get_opcodes(self, known_opcodes=None):
        """Return sorted list of opcode summaries with auto-tags."""
        with self._lock:
            result = []
            for opcode, group in self.opcode_groups.items():
                tags = _auto_tag(group)
                summary = group.summary(auto_tags=tags)
                # Attach user label if present
                if opcode in self.labels:
                    summary["label"] = self.labels[opcode]
                # Attach known opcode name if addon provides it
                if known_opcodes and opcode in known_opcodes:
                    summary["known_name"] = known_opcodes[opcode]
                result.append(summary)
            # Sort by count descending
            result.sort(key=lambda x: x["count"], reverse=True)
            return result

    def get_group(self, opcode):
        """Return an OpcodeGroup by opcode value, or None."""
        with self._lock:
            return self.opcode_groups.get(opcode)

    def start_baseline(self):
        """Snapshot current opcode counts as a baseline."""
        with self._lock:
            self.baseline = {op: g.count for op, g in self.opcode_groups.items()}

    def compute_diff(self):
        """Compare current state against baseline. Returns list of diffs."""
        if self.baseline is None:
            return []
        with self._lock:
            diffs = []
            for opcode, group in self.opcode_groups.items():
                baseline_count = self.baseline.get(opcode, 0)
                delta = group.count - baseline_count
                if delta <= 0:
                    continue
                diffs.append({
                    "opcode": opcode,
                    "opcode_hex": f"0x{opcode:04x}",
                    "baseline_count": baseline_count,
                    "current_count": group.count,
                    "delta": delta,
                    "is_new": baseline_count == 0,
                    "rate": round(group.rate_per_sec, 1),
                    "label": self.labels.get(opcode, ""),
                })
            diffs.sort(key=lambda x: (not x["is_new"], -x["delta"]))
            return diffs

    def clear_baseline(self):
        self.baseline = None

    def set_label(self, opcode, label):
        if label:
            self.labels[opcode] = label
        else:
            self.labels.pop(opcode, None)


# ---------------------------------------------------------------------------
# Auto-tagging heuristics (quick scan, runs on every opcode table refresh)
# ---------------------------------------------------------------------------

def _auto_tag(group):
    """Generate quick auto-tags for an opcode group based on sample inspection."""
    tags = []
    if not group.samples:
        return tags

    sample = group.samples[-1]  # most recent sample

    # Check for float triplets (XYZ coordinates)
    if len(sample) >= 12:
        _check_float_triplet(sample, tags)

    # Check for null-terminated strings
    if len(sample) >= 4:
        _check_strings(sample, tags)

    # Check for counter/sequence at offset 0
    if len(sample) >= 2 and len(group.samples) >= 3:
        _check_counter(group.samples, tags)

    # Check for length-prefixed data
    if len(sample) >= 4:
        _check_length_prefix(sample, tags)

    return tags


def _check_float_triplet(data, tags):
    """Look for 3 consecutive IEEE floats that could be coordinates."""
    # Check common offsets where coords appear
    for offset in range(0, min(len(data) - 11, 32), 4):
        try:
            x, y, z = struct.unpack_from("<fff", data, offset)
            # EQ world coords are typically -50000 to 50000
            if all(-100000 < v < 100000 for v in (x, y, z)):
                if not all(v == 0 for v in (x, y, z)):
                    if all(not (math.isnan(v) or math.isinf(v)) for v in (x, y, z)):
                        tags.append(f"xyz-floats @{offset}")
                        return
        except struct.error:
            break


def _check_strings(data, tags):
    """Look for null-terminated ASCII strings."""
    i = 0
    found = False
    while i < len(data) - 3:
        if 32 <= data[i] < 127:
            # Start of potential string
            end = i
            while end < len(data) and 32 <= data[end] < 127:
                end += 1
            length = end - i
            if length >= 4 and end < len(data) and data[end] == 0:
                tags.append(f"string @{i}")
                found = True
                if found:
                    return
                i = end + 1
                continue
        i += 1


def _check_counter(samples, tags):
    """Check if the first 2 bytes increment across recent samples."""
    vals = []
    for s in list(samples)[-5:]:
        if len(s) >= 2:
            vals.append(struct.unpack_from("<H", s, 0)[0])
    if len(vals) >= 3:
        diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
        if all(d == 1 for d in diffs):
            tags.append("counter @0")


def _check_length_prefix(data, tags):
    """Check for a 2-byte LE length prefix followed by that many bytes."""
    for offset in (0, 2, 4):
        if offset + 2 > len(data):
            break
        prefix_val = struct.unpack_from("<H", data, offset)[0]
        if 4 <= prefix_val <= len(data) - offset - 2:
            remaining = len(data) - offset - 2
            if prefix_val == remaining:
                tags.append(f"len-prefix @{offset}")
                return


# ---------------------------------------------------------------------------
# Deep field analysis (runs on demand for a single opcode)
# ---------------------------------------------------------------------------

def analyze_fields(group):
    """Run heuristic field analysis on an OpcodeGroup's samples.

    Returns a list of field guesses:
      [{"offset": int, "size": int, "type": str, "confidence": str,
        "sample_values": [str, ...], "notes": str}, ...]
    """
    samples = list(group.samples)
    if not samples:
        return []

    # Determine the analysis length (minimum sample size if variable)
    min_len = min(len(s) for s in samples)
    if min_len == 0:
        return []

    # Step 1: Build fixed/variable byte mask
    mask = _build_byte_mask(samples, min_len)

    # Step 2: Segment into contiguous regions
    regions = _segment_regions(mask, min_len)

    # Step 3: Classify each region
    fields = []
    for start, end, is_fixed in regions:
        size = end - start
        field = {
            "offset": start,
            "size": size,
            "type": "fixed" if is_fixed else "unknown",
            "confidence": "high" if is_fixed else "low",
            "sample_values": [],
            "notes": "",
        }

        if is_fixed:
            # Show the fixed value
            val = samples[0][start:end]
            field["sample_values"] = [val.hex()]
            field["notes"] = "constant across all samples"
        else:
            # Try type detection
            _classify_variable_field(field, samples, start, end)

        fields.append(field)

    # Handle variable-length tail if samples differ in size
    if not group.size_fixed and min_len < max(len(s) for s in samples):
        fields.append({
            "offset": min_len,
            "size": -1,
            "type": "variable-tail",
            "confidence": "low",
            "sample_values": [],
            "notes": f"payload extends beyond {min_len} bytes in some samples",
        })

    return fields


def _build_byte_mask(samples, length):
    """Compare samples byte-by-byte. Returns list of bools: True = fixed."""
    if len(samples) < 2:
        # With one sample we can't determine fixed vs variable
        return [False] * length

    ref = samples[0]
    mask = [True] * length
    for s in samples[1:]:
        for i in range(length):
            if mask[i] and s[i] != ref[i]:
                mask[i] = False
    return mask


def _segment_regions(mask, length):
    """Group consecutive bytes with same fixed/variable status.

    Returns list of (start, end, is_fixed) tuples.
    """
    if not mask:
        return []

    regions = []
    start = 0
    current = mask[0]
    for i in range(1, length):
        if mask[i] != current:
            regions.append((start, i, current))
            start = i
            current = mask[i]
    regions.append((start, length, current))
    return regions


def _classify_variable_field(field, samples, start, end):
    """Try to identify the type of a variable byte region."""
    size = end - start

    # Extract this region from recent samples
    extracts = [s[start:end] for s in samples[-10:] if len(s) >= end]
    if not extracts:
        return

    # Show sample values (hex)
    field["sample_values"] = [e.hex() for e in extracts[:5]]

    # Try float (4 bytes)
    if size == 4:
        try:
            vals = [struct.unpack_from("<f", e, 0)[0] for e in extracts]
            if all(-100000 < v < 100000 and not math.isnan(v) and not math.isinf(v) for v in vals):
                field["type"] = "float LE"
                field["confidence"] = "medium"
                field["sample_values"] = [f"{v:.4f}" for v in vals[:5]]
                # Check for coordinate-like values
                if all(-50000 < v < 50000 for v in vals):
                    field["notes"] = "could be a coordinate"
                return
        except struct.error:
            pass

    # Try float triplet (12 bytes)
    if size == 12:
        try:
            triplets = [struct.unpack_from("<fff", e, 0) for e in extracts]
            if all(all(-100000 < v < 100000 and not math.isnan(v) and not math.isinf(v)
                       for v in t) for t in triplets):
                field["type"] = "float3 LE (xyz?)"
                field["confidence"] = "medium"
                field["sample_values"] = [f"({t[0]:.2f}, {t[1]:.2f}, {t[2]:.2f})" for t in triplets[:5]]
                field["notes"] = "3 floats — likely coordinates"
                return
        except struct.error:
            pass

    # Try uint16 LE (2 bytes)
    if size == 2:
        try:
            vals = [struct.unpack_from("<H", e, 0)[0] for e in extracts]
            # Check for incrementing counter
            if len(vals) >= 3:
                diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
                if all(d == 1 for d in diffs):
                    field["type"] = "uint16 LE (counter)"
                    field["confidence"] = "high"
                    field["sample_values"] = [str(v) for v in vals[:5]]
                    field["notes"] = "incrementing by 1"
                    return
            field["type"] = "uint16 LE"
            field["confidence"] = "low"
            field["sample_values"] = [str(v) for v in vals[:5]]
            return
        except struct.error:
            pass

    # Try uint32 LE (4 bytes) — if float didn't match
    if size == 4:
        try:
            vals = [struct.unpack_from("<I", e, 0)[0] for e in extracts]
            if len(vals) >= 3:
                diffs = [vals[i+1] - vals[i] for i in range(len(vals)-1)]
                if all(d == 1 for d in diffs):
                    field["type"] = "uint32 LE (counter)"
                    field["confidence"] = "high"
                    field["sample_values"] = [str(v) for v in vals[:5]]
                    field["notes"] = "incrementing by 1"
                    return
            # Check if values are stable (same entity ID?)
            if len(set(vals)) == 1:
                field["type"] = "uint32 LE (stable)"
                field["confidence"] = "medium"
                field["sample_values"] = [f"0x{v:08x}" for v in vals[:5]]
                field["notes"] = "same value across samples — could be an ID"
                return
            field["type"] = "uint32 LE"
            field["confidence"] = "low"
            field["sample_values"] = [f"0x{v:08x}" for v in vals[:5]]
            return
        except struct.error:
            pass

    # Try null-terminated string (variable size)
    if size >= 4:
        _try_string_field(field, extracts)


def _try_string_field(field, extracts):
    """Check if a field region looks like a null-terminated string."""
    ascii_count = 0
    for e in extracts:
        printable = sum(1 for b in e if 32 <= b < 127)
        if printable >= len(e) * 0.7 and len(e) >= 4:
            ascii_count += 1
    if ascii_count >= len(extracts) * 0.7:
        field["type"] = "string"
        field["confidence"] = "medium"
        field["sample_values"] = []
        for e in extracts[:5]:
            text = bytes(b if 32 <= b < 127 else ord('.') for b in e).decode("ascii")
            # Trim at null terminator
            null_pos = text.find('\x00')
            if null_pos >= 0:
                text = text[:null_pos]
            field["sample_values"].append(repr(text))
        field["notes"] = "mostly ASCII"


# ---------------------------------------------------------------------------
# Label persistence
# ---------------------------------------------------------------------------

def save_labels(labels, path):
    """Save opcode labels to a JSON file."""
    # Convert int keys to hex strings for JSON
    data = {f"0x{k:04x}": v for k, v in labels.items()}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_labels(path):
    """Load opcode labels from a JSON file. Returns dict[int, str]."""
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return {int(k, 16): v for k, v in data.items()}
    except (json.JSONDecodeError, ValueError):
        return {}
