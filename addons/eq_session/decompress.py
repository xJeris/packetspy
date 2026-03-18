"""Decompression for EQ session protocol payloads.

After stripping CRC, the first byte of the payload region indicates
compression: 0x5a = deflate compressed, 0xa5 = uncompressed.
"""

import zlib


def decompress_payload(data):
    """Decompress EQ payload data.

    Args:
        data: Payload bytes (first byte is the compression flag).

    Returns:
        (decompressed_bytes, was_compressed) tuple.
    """
    if not data:
        return data, False

    flag = data[0]

    if flag == 0x5a:
        # Deflate compressed (raw deflate, no zlib header)
        try:
            decompressed = zlib.decompress(data[1:], -15)
            return decompressed, True
        except zlib.error:
            # Decompression failed — return raw bytes after flag
            return data[1:], False

    elif flag == 0xa5:
        # Uncompressed marker — skip the flag byte
        return data[1:], False

    else:
        # No recognized compression marker
        return data, False
