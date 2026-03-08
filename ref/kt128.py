from .turboshake import turboshake128
from .encodings import length_encode

S_CHUNK = 8192  # KT128 chunk size (bytes).
C = 32          # Chaining value size (bytes).

# Sakura hop frame: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving suffix for I = infinity.
SAKURA_SUFFIX = b"\xff\xff"


def kt128(message: bytes, custom_string: bytes, output_len: int) -> bytes:
    """KangarooTwelve as specified in RFC 9861."""
    # Append customization string with length encoding.
    S = message + custom_string + length_encode(len(custom_string))

    # Single-chunk fast path: message hop '11' -> 0x07.
    if len(S) <= S_CHUNK:
        return turboshake128(S, 0x07, output_len)

    # Multi-chunk: split into S_CHUNK-byte chunks.
    chunks = [S[i : i + S_CHUNK] for i in range(0, len(S), S_CHUNK)]
    n = len(chunks) - 1  # Number of leaf chunks.

    # Compute chaining values for leaf chunks (1..n).
    cvs = [turboshake128(chunk, 0x0B, C) for chunk in chunks[1:]]

    # Build final node input.
    final_node = chunks[0] + HOP_FRAME
    for cv in cvs:
        final_node += cv
    final_node += length_encode(n) + SAKURA_SUFFIX

    # Chaining hop '01' -> 0x06.
    return turboshake128(final_node, 0x06, output_len)
