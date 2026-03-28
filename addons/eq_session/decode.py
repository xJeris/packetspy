"""XOR decode for EQ session protocol payloads.

After CRC stripping and before decompression, the SOE session protocol
applies 1-2 XOR encoding passes over data bytes.  The encode key is a
4-byte value from OP_SessionResponse, and encode_pass1 / encode_pass2
flags indicate which passes are active.

Algorithm (from EQEmu / OpenZone documentation):
  Pass 1 — XOR each byte with a rolling key derived from encode_key.
  Pass 2 — XOR each byte with the previous byte (cipher-block-chaining style).

Both passes operate on the data AFTER the 2-byte session opcode header
(i.e. starting at byte index 2).
"""

def decode_payload(data, encode_key, encode_pass1=0, encode_pass2=0):
    """Decode an XOR-encoded EQ session payload in-place.

    Args:
        data: Payload bytes (with 2-byte session opcode header intact).
              Must already have CRC stripped.
        encode_key: 4-byte key from OP_SessionResponse (as int).
        encode_pass1: Flag from OP_SessionResponse (non-zero = enabled).
        encode_pass2: Flag from OP_SessionResponse (non-zero = enabled).

    Returns:
        (decoded_bytes, was_decoded) tuple.
    """
    if not data or len(data) <= 2:
        return data, False

    if not encode_pass1 and not encode_pass2:
        return data, False

    # Work on a mutable copy; skip the 2-byte session opcode header
    buf = bytearray(data)

    if encode_pass2:
        _xor_pass2_decode(buf)

    if encode_pass1:
        _xor_pass1_decode(buf, encode_key)

    return bytes(buf), True


def _xor_pass1_decode(buf, encode_key):
    """Pass 1: rolling XOR using the encode key as seed."""
    key = encode_key
    for i in range(2, len(buf)):
        # Rotate key: this matches the EQEmu CRC/encode key schedule
        key = ((key >> 1) | (key << 31)) & 0xFFFFFFFF
        buf[i] ^= (key & 0xFF)


def _xor_pass2_decode(buf):
    """Pass 2: CBC-style — each byte was XORed with the previous byte during encoding.

    To decode, walk backwards (last byte first) and XOR with the prior byte.
    """
    for i in range(len(buf) - 1, 2, -1):
        buf[i] ^= buf[i - 1]
