"""Thyrse Protocol — core transcript machinery with init, mix, and derive."""

import hmac as _hmac
from .encodings import left_encode, right_encode, encode_string
from .kt128 import kt128
from .treewrap import encrypt_and_mac, decrypt_and_mac

C = 32   # TreeWrap key and tag size (bytes).
H = 64   # Chain value size (bytes).

# Operation codes.
OP_INIT    = 0x01
OP_MIX     = 0x02
OP_FORK    = 0x03
OP_DERIVE  = 0x04
OP_RATCHET = 0x05
OP_MASK    = 0x06
OP_SEAL    = 0x07
OP_CHAIN   = 0x08

# KT128 customization strings.
CS_CHAIN       = 0x20
CS_DERIVE      = 0x21
CS_MASK_KEY    = 0x22
CS_SEAL_KEY    = 0x23
CS_RATCHET     = 0x24


class Protocol:
    def __init__(self):
        self.transcript = bytearray()

    def _append_frame(self, op: int, label: bytes, value: bytes = b""):
        start = len(self.transcript)
        self.transcript += bytes([op]) + encode_string(label) + value
        self.transcript += right_encode(start)

    def _finalize(self, customization_strings: dict[int, int]) -> dict[int, bytes]:
        T = bytes(self.transcript)
        return {cs: kt128(T, bytes([cs]), length)
                for cs, length in customization_strings.items()}

    def _reset_chain(self, origin_op: int, *values: bytes):
        payload = bytes([origin_op]) + left_encode(len(values))
        for v in values:
            payload += encode_string(v)
        self.transcript = bytearray()
        self._append_frame(OP_CHAIN, b"", payload)

    def init(self, label: bytes):
        self._append_frame(OP_INIT, label)

    def mix(self, label: bytes, data: bytes):
        self._append_frame(OP_MIX, label, data)

    def derive(self, label: bytes, output_len: int) -> bytes:
        assert output_len > 0
        self._append_frame(OP_DERIVE, label, left_encode(output_len))
        results = self._finalize({CS_CHAIN: H, CS_DERIVE: output_len})
        self._reset_chain(OP_DERIVE, results[CS_CHAIN])
        return results[CS_DERIVE]

    def ratchet(self, label: bytes):
        self._append_frame(OP_RATCHET, label)
        results = self._finalize({CS_RATCHET: H})
        self._reset_chain(OP_RATCHET, results[CS_RATCHET])

    def mask(self, label: bytes, plaintext: bytes) -> bytes:
        self._append_frame(OP_MASK, label)
        results = self._finalize({CS_CHAIN: H, CS_MASK_KEY: C})
        ct, tag = encrypt_and_mac(results[CS_MASK_KEY], plaintext)
        self._reset_chain(OP_MASK, results[CS_CHAIN], tag)
        return ct

    def unmask(self, label: bytes, ciphertext: bytes) -> bytes:
        self._append_frame(OP_MASK, label)
        results = self._finalize({CS_CHAIN: H, CS_MASK_KEY: C})
        pt, tag = decrypt_and_mac(results[CS_MASK_KEY], ciphertext)
        self._reset_chain(OP_MASK, results[CS_CHAIN], tag)
        return pt

    def seal(self, label: bytes, plaintext: bytes) -> bytes:
        self._append_frame(OP_SEAL, label)
        results = self._finalize({CS_CHAIN: H, CS_SEAL_KEY: C})
        ct, tag = encrypt_and_mac(results[CS_SEAL_KEY], plaintext)
        self._reset_chain(OP_SEAL, results[CS_CHAIN], tag)
        return ct + tag

    def open(self, label: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
        self._append_frame(OP_SEAL, label)
        results = self._finalize({CS_CHAIN: H, CS_SEAL_KEY: C})
        pt, computed_tag = decrypt_and_mac(results[CS_SEAL_KEY], ciphertext)
        self._reset_chain(OP_SEAL, results[CS_CHAIN], computed_tag)
        if not _hmac.compare_digest(computed_tag, tag):
            return None
        return pt
