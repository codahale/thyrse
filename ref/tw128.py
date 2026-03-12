from .duplex import (
    C,
    _DuplexState, _duplex_pad_permute, _duplex_encrypt,
    _duplex_decrypt, _duplex_absorb,
)
from .encodings import encode_string, length_encode

# region: internal_functions
def _leaf_encrypt(base: _DuplexState, index: int, chunk: bytes) -> tuple[bytes, bytes]:
    """Encrypt a leaf chunk, returning (ciphertext, chain_value)."""
    L = _DuplexState(bytearray(base.S), base.pos)
    L = _duplex_absorb(L, index.to_bytes(8, "little"))
    L = _duplex_pad_permute(L, 0x08)
    L, ct = _duplex_encrypt(L, chunk)
    L = _duplex_pad_permute(L, 0x0B)
    return ct, bytes(L.S[:C])

def _leaf_decrypt(base: _DuplexState, index: int, chunk: bytes) -> tuple[bytes, bytes]:
    """Decrypt a leaf chunk, returning (plaintext, chain_value)."""
    L = _DuplexState(bytearray(base.S), base.pos)
    L = _duplex_absorb(L, index.to_bytes(8, "little"))
    L = _duplex_pad_permute(L, 0x08)
    L, pt = _duplex_decrypt(L, chunk)
    L = _duplex_pad_permute(L, 0x0B)
    return pt, bytes(L.S[:C])
# endregion

# region: core_functions
import hmac

K_L = 32  # Key length (bytes).
TAU = 32  # Tag size (bytes).
B = 8192  # Chunk size (bytes).

# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def encrypt_and_mac(K: bytes, N: bytes, AD: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypt, returning (ciphertext, tag) as separate values."""
    assert len(K) == K_L, "K must be exactly 32 bytes"

    n = max(1, -(-len(M) // B))
    chunks = [M[i * B : (i + 1) * B] for i in range(n)]

    # Build base state from context prefix.
    prefix = encode_string(K) + encode_string(N) + encode_string(AD)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Initialize and encrypt on the final node.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, ct0 = _duplex_encrypt(F, chunks[0])

    if n == 1:
        F = _duplex_pad_permute(F, 0x07)
        return ct0, bytes(F.S[:TAU])

    # Multi-node: absorb hop frame, process leaves, absorb chain values.
    F = _duplex_absorb(F, HOP_FRAME)
    out_parts = [ct0]
    for i, chunk in enumerate(chunks[1:], start=1):
        ct_i, cv = _leaf_encrypt(base, i, chunk)
        out_parts.append(ct_i)
        F = _duplex_absorb(F, cv)

    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])

def decrypt_and_mac(K: bytes, N: bytes, AD: bytes, ct: bytes) -> tuple[bytes, bytes]:
    """Decrypt without tag verification, returning (unverified_plaintext, tag)."""
    assert len(K) == K_L, "K must be exactly 32 bytes"

    n = max(1, -(-len(ct) // B))
    chunks = [ct[i * B : (i + 1) * B] for i in range(n)]

    # Build base state from context prefix.
    prefix = encode_string(K) + encode_string(N) + encode_string(AD)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Initialize and decrypt on the final node.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, pt0 = _duplex_decrypt(F, chunks[0])

    if n == 1:
        F = _duplex_pad_permute(F, 0x07)
        return pt0, bytes(F.S[:TAU])

    # Multi-node: absorb hop frame, process leaves, absorb chain values.
    F = _duplex_absorb(F, HOP_FRAME)
    out_parts = [pt0]
    for i, chunk in enumerate(chunks[1:], start=1):
        pt_i, cv = _leaf_decrypt(base, i, chunk)
        out_parts.append(pt_i)
        F = _duplex_absorb(F, cv)

    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])
# endregion

# region: aead_functions
def tw128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    """AEAD encryption: returns ct ‖ tag."""
    ct, tag = encrypt_and_mac(K, N, AD, M)
    return ct + tag

def tw128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    """AEAD decryption: verifies tag and returns plaintext or None."""
    if len(ct_tag) < TAU:
        return None
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(K, N, AD, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
# endregion
