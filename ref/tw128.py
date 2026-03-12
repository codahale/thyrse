from .duplex import (
    C, TAU, B,
    _DuplexState, _duplex_pad_permute, _duplex_encrypt,
    _duplex_decrypt, _duplex_absorb,
)
from .encodings import encode_string, length_encode

# region: internal_functions
# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def _tree_process(key: bytes, nonce: bytes, ad: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for TW128 encrypt/decrypt."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    op = _duplex_encrypt if direction == "E" else _duplex_decrypt

    # Build base state: absorb encode_string(K) || encode_string(N) || encode_string(AD).
    prefix = encode_string(key) + encode_string(nonce) + encode_string(ad)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Final node: clone base, absorb LEU64(0), pad_permute 0x08.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, ct0 = op(F, chunks[0])
    out_parts = [ct0]

    if n == 1:
        # Single node: message hop '11' -> 0x07
        F = _duplex_pad_permute(F, 0x07)
        return out_parts[0], bytes(F.S[:TAU])

    # Multi-node: message hop framing '110^{62}'
    F = _duplex_absorb(F, HOP_FRAME)

    # Leaves 1..n-1: independent, parallel.
    cvs = []
    for i, chunk in enumerate(chunks[1:], start=1):
        # Clone base, absorb LEU64(i), pad_permute 0x08.
        L = _DuplexState(bytearray(base.S), base.pos)
        L = _duplex_absorb(L, i.to_bytes(8, "little"))
        L = _duplex_pad_permute(L, 0x08)
        L, ct_i = op(L, chunk)
        out_parts.append(ct_i)
        L = _duplex_pad_permute(L, 0x0B)
        cvs.append(bytes(L.S[:C]))

    # Absorb chain values into final node.
    for cv in cvs:
        F = _duplex_absorb(F, cv)

    # Chaining hop suffix.
    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)

    # Chaining hop '01' -> 0x06
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])
# endregion

# region: aead_functions
import hmac

def tw128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    assert len(K) == C, "K must be exactly 32 bytes"
    ct, tag = _tree_process(K, N, AD, M, "E")
    return ct + tag

def tw128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    assert len(K) == C, "K must be exactly 32 bytes"
    if len(ct_tag) < TAU:
        return None
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = _tree_process(K, N, AD, ct, "D")
    return pt if hmac.compare_digest(tag, tag_expected) else None
# endregion
