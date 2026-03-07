from .keccak import keccak_p1600

# region: duplex_all
from collections import namedtuple

R = 168   # Sponge rate (bytes).
C = 32    # Capacity (bytes); key and chain value size.
TAU = 32  # Tag size (bytes).
B = 8192  # Chunk size (bytes).

# S: 200-byte Keccak state (bytearray). pos: current offset into the rate.
_DuplexState = namedtuple("_DuplexState", ["S", "pos"])

def _duplex_pad_permute(D: _DuplexState, domain_byte: int) -> _DuplexState:
    """Apply TurboSHAKE padding and permute. Resets pos to 0."""
    S = bytearray(D.S)
    S[D.pos] ^= domain_byte
    S[R - 1] ^= 0x80
    keccak_p1600(S)
    return _DuplexState(S, 0)

def _duplex_encrypt(D: _DuplexState, plaintext: bytes) -> tuple[_DuplexState, bytes]:
    """Encrypt plaintext, overwriting the rate with ciphertext."""
    S, pos = bytearray(D.S), D.pos
    ct = bytearray()
    for p in plaintext:
        ct.append(p ^ S[pos])
        S[pos] = ct[-1]
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos), bytes(ct)

def _duplex_decrypt(D: _DuplexState, ciphertext: bytes) -> tuple[_DuplexState, bytes]:
    """Decrypt ciphertext, overwriting the rate with ciphertext."""
    S, pos = bytearray(D.S), D.pos
    pt = bytearray()
    for c in ciphertext:
        pt.append(c ^ S[pos])
        S[pos] = c
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos), bytes(pt)

def _duplex_absorb(D: _DuplexState, data: bytes) -> _DuplexState:
    """XOR-absorb data into the rate."""
    S, pos = bytearray(D.S), D.pos
    for b in data:
        S[pos] ^= b
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos)
# endregion
