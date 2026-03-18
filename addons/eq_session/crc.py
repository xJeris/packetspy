"""CRC stripping for EQ session protocol packets.

EQ appends a CRC (2 or 4 bytes) to the end of session protocol packets.
The byte count is negotiated in OP_SessionResponse.
For now we just strip the CRC bytes; full validation is a future enhancement.
"""


def strip_crc(data, crc_bytes):
    """Remove CRC from end of packet data.

    Args:
        data: Raw packet bytes (after session header).
        crc_bytes: Number of CRC bytes to strip (from OP_SessionResponse).

    Returns:
        Data with CRC removed.
    """
    if crc_bytes and len(data) > crc_bytes:
        return data[:-crc_bytes]
    return data
