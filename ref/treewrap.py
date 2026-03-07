import hmac
from .duplex import (
    R, C, TAU, B,
    _DuplexState, _duplex_pad_permute, _duplex_encrypt,
    _duplex_decrypt, _duplex_absorb,
)
from .kt128 import turboshake128
from .encodings import encode_string, length_encode

# region: internal_functions
# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def _tree_process(key: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for EncryptAndMAC / DecryptAndMAC."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    op = _duplex_encrypt if direction == "E" else _duplex_decrypt

    # Final node: absorb key || LEU64(0) and pad to key the duplex.
    F = _DuplexState(bytearray(200), 0)
    F = _duplex_absorb(F, key + (0).to_bytes(8, "little"))
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
        # Absorb key || LEU64(i) and pad to key the leaf duplex.
        L = _DuplexState(bytearray(200), 0)
        L = _duplex_absorb(L, key + i.to_bytes(8, "little"))
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

def encrypt_and_mac(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, plaintext, "E")

def decrypt_and_mac(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, ciphertext, "D")
# endregion

# region: aead_functions
import hmac

def treewrap128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    assert len(K) == C, "K must be exactly 32 bytes"
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x09, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    assert len(K) == C, "K must be exactly 32 bytes"
    if len(ct_tag) < TAU:
        return None
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x09, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
# endregion
