"""TW128 wrapper — delegates to the treewrap reference implementation."""

import sys
from pathlib import Path

# Add treewrap repo so we can import the canonical reference.
_TREEWRAP = Path(__file__).resolve().parent.parent.parent / "treewrap"
if str(_TREEWRAP) not in sys.path:
    sys.path.insert(0, str(_TREEWRAP))

from tw128 import _treewrap, _K, _NONCE, _TAG  # noqa: E402

KL = _K
TAU = _TAG
NONCE = _NONCE


def _pad_nonce(n: bytes) -> bytes:
    """Pad or validate nonce to 16 bytes."""
    if len(n) == _NONCE:
        return n
    if len(n) == 0:
        return bytes(_NONCE)
    raise ValueError(f"nonce must be 0 or {_NONCE} bytes, got {len(n)}")


def encrypt_and_mac(K: bytes, N: bytes, AD: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypt, returning (ciphertext, tag) as separate values."""
    y, tag = _treewrap(K, _pad_nonce(N), AD, M, False)
    return y, tag


def decrypt_and_mac(K: bytes, N: bytes, AD: bytes, ct: bytes) -> tuple[bytes, bytes]:
    """Decrypt without tag verification, returning (unverified_plaintext, tag)."""
    pt, tag = _treewrap(K, _pad_nonce(N), AD, ct, True)
    return pt, tag


def tw128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    """AEAD encryption: returns ct || tag."""
    ct, tag = encrypt_and_mac(K, N, AD, M)
    return ct + tag


def tw128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    """AEAD decryption: verifies tag and returns plaintext or None."""
    import hmac
    if len(ct_tag) < TAU:
        return None
    ct, expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(K, N, AD, ct)
    return pt if hmac.compare_digest(tag, expected) else None
