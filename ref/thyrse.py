"""Thyrse Protocol — core transcript machinery with init, mix, and derive."""

import hmac
from .encodings import left_encode, right_encode, encode_string
from .kt128 import kt128
from .tw128 import encrypt_and_mac, decrypt_and_mac

# region: constants
C = 32   # TW128 key and tag size (bytes).
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


def _encode_frame(start: int, op: int, label: bytes, value: bytes = b"") -> bytes:
    """Encode a TKDF frame: op ‖ encode_string(label) ‖ value ‖ right_encode(start).

    Each frame records its own start position via right_encode, making the
    transcript recoverable (§5).
    """
    return bytes([op]) + encode_string(label) + value + right_encode(start)


def _encode_chain(origin_op: int, *values: bytes) -> bytearray:
    """Encode a CHAIN frame that replaces the transcript after a finalizing operation.

    Finalizing operations (Derive, Ratchet, Mask, Seal) evaluate KT128 over
    the current transcript, then replace it with a single CHAIN frame.  The
    frame carries the origin operation code and all derived values so the
    transcript records which operation produced the chain and what was fed
    back into it.
    """
    payload = bytes([origin_op]) + left_encode(len(values))
    for v in values:
        payload += encode_string(v)
    return bytearray(_encode_frame(0, OP_CHAIN, b"", payload))
# endregion


# region: protocol_core
class Protocol:
    def __init__(self):
        self.transcript = bytearray()
    # endregion

    # region: init
    def init(self, label: bytes):
        self.transcript += _encode_frame(len(self.transcript), OP_INIT, label)
    # endregion

    # region: mix
    def mix(self, label: bytes, data: bytes):
        self.transcript += _encode_frame(len(self.transcript), OP_MIX, label, data)
    # endregion

    # region: derive
    def derive(self, label: bytes, output_len: int) -> bytes:
        assert output_len > 0
        self.transcript += _encode_frame(
            len(self.transcript), OP_DERIVE, label, left_encode(output_len))
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        output = kt128(T, bytes([CS_DERIVE]), output_len)
        self.transcript = _encode_chain(OP_DERIVE, chain)
        return output
    # endregion

    # region: ratchet
    def ratchet(self, label: bytes):
        self.transcript += _encode_frame(
            len(self.transcript), OP_RATCHET, label)
        T = bytes(self.transcript)
        ratchet_value = kt128(T, bytes([CS_RATCHET]), H)
        self.transcript = _encode_chain(OP_RATCHET, ratchet_value)
    # endregion

    # region: mask_unmask
    def mask(self, label: bytes, plaintext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_MASK, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        mask_key = kt128(T, bytes([CS_MASK_KEY]), C)
        ct, tag = encrypt_and_mac(mask_key, b"", b"", plaintext)
        self.transcript = _encode_chain(OP_MASK, chain, tag)
        return ct

    def unmask(self, label: bytes, ciphertext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_MASK, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        mask_key = kt128(T, bytes([CS_MASK_KEY]), C)
        pt, tag = decrypt_and_mac(mask_key, b"", b"", ciphertext)
        self.transcript = _encode_chain(OP_MASK, chain, tag)
        return pt
    # endregion

    # region: seal_open
    def seal(self, label: bytes, plaintext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_SEAL, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        seal_key = kt128(T, bytes([CS_SEAL_KEY]), C)
        ct, tag = encrypt_and_mac(seal_key, b"", b"", plaintext)
        self.transcript = _encode_chain(OP_SEAL, chain, tag)
        return ct + tag

    def open(self, label: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
        self.transcript += _encode_frame(
            len(self.transcript), OP_SEAL, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        seal_key = kt128(T, bytes([CS_SEAL_KEY]), C)
        pt, computed_tag = decrypt_and_mac(seal_key, b"", b"", ciphertext)
        self.transcript = _encode_chain(OP_SEAL, chain, computed_tag)
        if not hmac.compare_digest(computed_tag, tag):
            return None
        return pt
    # endregion

    # region: fork
    def fork(self, label: bytes, *values: bytes) -> list["Protocol"]:
        N = len(values)
        snapshot = bytes(self.transcript)
        self.transcript += _encode_frame(len(self.transcript), OP_FORK, label,
            left_encode(N) + left_encode(0) + encode_string(b""))
        clones = []
        for i, val in enumerate(values, start=1):
            clone = Protocol()
            clone.transcript = bytearray(snapshot)
            clone.transcript += _encode_frame(len(clone.transcript), OP_FORK,
                label, left_encode(N) + left_encode(i) + encode_string(val))
            clones.append(clone)
        return clones
    # endregion

    # region: clone_clear
    def clone(self) -> "Protocol":
        copy = Protocol()
        copy.transcript = bytearray(self.transcript)
        return copy

    def clear(self):
        for i in range(len(self.transcript)):
            self.transcript[i] = 0
        self.transcript = bytearray()
    # endregion


# region: usage_aead
def _example_aead(key_material, nonce, associated_data, plaintext):
    p = Protocol()
    p.init(b"com.example.myprotocol")
    p.mix(b"key", key_material)
    p.mix(b"nonce", nonce)
    p.mix(b"ad", associated_data)
    ciphertext_tag = p.seal(b"message", plaintext)
# endregion


# region: usage_aead_decrypt
def _example_aead_decrypt(key_material, nonce, associated_data, ciphertext, tag):
    p = Protocol()
    p.init(b"com.example.myprotocol")
    p.mix(b"key", key_material)
    p.mix(b"nonce", nonce)
    p.mix(b"ad", associated_data)
    plaintext = p.open(b"message", ciphertext, tag)
# endregion
