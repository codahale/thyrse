# region: encodings_tw128
def length_encode(x: int) -> bytes:
    """RFC 9861 length_encode: big-endian, no leading zeros, followed by byte count."""
    if x == 0:
        return b"\x00"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big") + bytes([n])

def left_encode(x: int) -> bytes:
    """NIST SP 800-185 left_encode: byte count, then big-endian value (at least one byte)."""
    if x == 0:
        return b"\x01\x00"
    n = (x.bit_length() + 7) // 8
    return bytes([n]) + x.to_bytes(n, "big")

def encode_string(x: bytes) -> bytes:
    """NIST SP 800-185 encode_string: left_encode(len(x) * 8) || x."""
    return left_encode(len(x) * 8) + x
# endregion

def right_encode(x: int) -> bytes:
    """NIST SP 800-185 right_encode: big-endian value (at least one byte), then byte count."""
    if x == 0:
        return b"\x00\x01"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big") + bytes([n])
