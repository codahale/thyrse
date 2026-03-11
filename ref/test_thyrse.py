"""Tests for Thyrse reference implementation."""

import unittest
from .encodings import right_encode
from .kt128 import kt128


def ptn(n: int) -> bytes:
    """KT128 test pattern: repeating 0x00..0xFA (251 values)."""
    return bytes(i % 251 for i in range(n))


class TestRightEncode(unittest.TestCase):
    def test_spec_examples(self):
        """§4 examples: right_encode(0) = 0x00 0x01, right_encode(127) = 0x7F 0x01, right_encode(256) = 0x01 0x00 0x02."""
        self.assertEqual(right_encode(0), b"\x00\x01")
        self.assertEqual(right_encode(127), b"\x7f\x01")
        self.assertEqual(right_encode(256), b"\x01\x00\x02")


class TestKT128(unittest.TestCase):
    """RFC 9861 Section 5 KT128 test vectors."""

    def test_empty_empty_32(self):
        out = kt128(b"", b"", 32)
        self.assertEqual(
            out.hex(),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5",
        )

    def test_empty_empty_64(self):
        out = kt128(b"", b"", 64)
        self.assertEqual(
            out.hex(),
            "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
            "4269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71",
        )

    def test_empty_empty_10032(self):
        out = kt128(b"", b"", 10032)
        self.assertEqual(
            out[-32:].hex(),
            "e8dc563642f7228c84684c898405d3a834799158c079b12880277a1d28e2ff6d",
        )

    def test_ptn1_empty_32(self):
        out = kt128(ptn(1), b"", 32)
        self.assertEqual(
            out.hex(),
            "2bda92450e8b147f8a7cb629e784a058efca7cf7d8218e02d345dfaa65244a1f",
        )

    def test_ptn17_empty_32(self):
        out = kt128(ptn(17), b"", 32)
        self.assertEqual(
            out.hex(),
            "6bf75fa2239198db4772e36478f8e19b0f371205f6a9a93a273f51df37122888",
        )

    def test_ptn289_empty_32(self):
        out = kt128(ptn(289), b"", 32)
        self.assertEqual(
            out.hex(),
            "0c315ebcdedbf61426de7dcf8fb725d1e74675d7f5327a5067f367b108ecb67c",
        )

    def test_ptn4913_empty_32(self):
        out = kt128(ptn(4913), b"", 32)
        self.assertEqual(
            out.hex(),
            "cb552e2ec77d9910701d578b457ddf772c12e322e4ee7fe417f92c758f0d59d0",
        )

    def test_ptn83521_empty_32(self):
        out = kt128(ptn(83521), b"", 32)
        self.assertEqual(
            out.hex(),
            "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe",
        )

    def test_empty_ptn1_32(self):
        out = kt128(b"", ptn(1), 32)
        self.assertEqual(
            out.hex(),
            "fab658db63e94a246188bf7af69a133045f46ee984c56e3c3328caaf1aa1a583",
        )

    def test_0xff_ptn41_32(self):
        out = kt128(b"\xff", ptn(41), 32)
        self.assertEqual(
            out.hex(),
            "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4",
        )

    def test_0xffx3_ptn1681_32(self):
        out = kt128(b"\xff\xff\xff", ptn(1681), 32)
        self.assertEqual(
            out.hex(),
            "c389e5009ae57120854c2e8c64670ac01358cf4c1baf89447a724234dc7ced74",
        )

    def test_0xffx7_ptn68921_32(self):
        out = kt128(b"\xff" * 7, ptn(68921), 32)
        self.assertEqual(
            out.hex(),
            "75d2f86a2e644566726b4fbcfc5657b9dbcf070c7b0dca06450ab291d7443bcf",
        )

    def test_ptn8191_empty_32(self):
        """Single-chunk boundary: 8191 + length_encode(0) = 8192 bytes."""
        out = kt128(ptn(8191), b"", 32)
        self.assertEqual(
            out.hex(),
            "1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6",
        )

    def test_ptn8192_empty_32(self):
        """Exactly 8192 bytes of message + 1 byte length_encode(0) = 8193 -> tree mode."""
        out = kt128(ptn(8192), b"", 32)
        self.assertEqual(
            out.hex(),
            "48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3",
        )

    def test_ptn8192_ptn8189_32(self):
        out = kt128(ptn(8192), ptn(8189), 32)
        self.assertEqual(
            out.hex(),
            "3ed12f70fb05ddb58689510ab3e4d23c6c6033849aa01e1d8c220a297fedcd0b",
        )

    def test_ptn8192_ptn8190_32(self):
        out = kt128(ptn(8192), ptn(8190), 32)
        self.assertEqual(
            out.hex(),
            "6a7c1b6a5cd0d8c9ca943a4a216cc64604559a2ea45f78570a15253d67ba00ae",
        )

    def test_custom_string_differs(self):
        """KT128 with custom string produces different output than without."""
        msg = bytes(range(256))
        out_with = kt128(msg, bytes(range(256)), 32)
        out_without = kt128(msg, b"", 32)
        self.assertNotEqual(out_with, out_without)

    def test_multi_chunk_differs_from_single(self):
        """Message larger than 8192 bytes triggers tree hashing."""
        msg = bytes(i % 256 for i in range(8193))
        out = kt128(msg, b"", 32)
        out_short = kt128(msg[:8192], b"", 32)
        self.assertNotEqual(out, out_short)


from .thyrse import Protocol


class TestInitDerive(unittest.TestCase):
    def test_init_derive_16_1(self):
        """§16.1: Init("test.vector") then Derive("output", 32)."""
        p = Protocol()
        p.init(b"test.vector")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), "25feba088971a4b573101369ea1c8d83e6f102c2dc46e5cceb81a0b97fca514c")

    def test_init_mix_mix_derive_16_2(self):
        """§16.2: Init + Mix + Mix + Derive."""
        p = Protocol()
        p.init(b"test.vector")
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), "0db4090efec2ba935dac63a18d88df04859d1dedf4a60f428393674520b67e39")


class TestRatchet(unittest.TestCase):
    def test_ratchet_16_5(self):
        """§16.5: Derive output differs with and without Ratchet."""
        p1 = Protocol()
        p1.init(b"test.vector")
        p1.mix(b"key", b"test-key-material")
        out1 = p1.derive(b"output", 32)
        self.assertEqual(out1.hex(), "b20333efd472bf1cafbdfcc7c4aef46ca9984b768dbf84e33006024bead07dcf")

        p2 = Protocol()
        p2.init(b"test.vector")
        p2.mix(b"key", b"test-key-material")
        p2.ratchet(b"forward-secrecy")
        out2 = p2.derive(b"output", 32)
        self.assertEqual(out2.hex(), "23be92e694890a8b3d6fb5b4885b3b5a63539ad8da6fc5e8e20cf34728dbeb91")


class TestMask(unittest.TestCase):
    def test_mask_seal_16_4(self):
        """§16.4: Init + Mix + Mask + Seal."""
        p = Protocol()
        p.init(b"test.vector")
        p.mix(b"key", b"test-key-material")
        masked = p.mask(b"unauthenticated", b"mask this data")
        self.assertEqual(masked.hex(), "21fc87f3008b3cff62fb2584c970")
        sealed = p.seal(b"authenticated", b"seal this data")
        self.assertEqual(sealed.hex(), "f078ea89c7dea34a821c8470544ec5a70061c75aa9de8a1d49e4a9e816455ca54f78e50a2a1981d1c0a47cfe4d20")

    def test_mask_unmask_roundtrip(self):
        """Mask then Unmask with identical transcripts recovers plaintext."""
        sender = Protocol()
        sender.init(b"test.vector")
        sender.mix(b"key", b"test-key-material")
        ct = sender.mask(b"data", b"secret message")

        receiver = Protocol()
        receiver.init(b"test.vector")
        receiver.mix(b"key", b"test-key-material")
        pt = receiver.unmask(b"data", ct)
        self.assertEqual(pt, b"secret message")


class TestSeal(unittest.TestCase):
    def test_seal_derive_16_3(self):
        """§16.3: Init + Mix + Seal + Derive."""
        p = Protocol()
        p.init(b"test.vector")
        p.mix(b"key", b"test-key-material")
        sealed = p.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), "dde795eebaaa663b55e904c1e4da1c6c6f1c770b9c90fd17b8add38741dd5e4c821ad0e5aeb4bbfbc18d89ebe4")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), "e6a99cd5ac77af8370dd09e5f1ea020b1ded0a7415a9dadcbe6133e917dd2498")

    def test_seal_open_roundtrip_16_7(self):
        """§16.7: Seal + Open round-trip."""
        sender = Protocol()
        sender.init(b"test.vector")
        sender.mix(b"key", b"test-key-material")
        sender.mix(b"nonce", b"test-nonce-value")
        sender.mix(b"ad", b"associated data")
        sealed = sender.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), "1383ffe1d63304655b9b94ae27f2a50ea1734e2df148381c2080d70ad86bac40e84d08e43b48b0b9f4a106156a")

        receiver = Protocol()
        receiver.init(b"test.vector")
        receiver.mix(b"key", b"test-key-material")
        receiver.mix(b"nonce", b"test-nonce-value")
        receiver.mix(b"ad", b"associated data")
        ct, tag = sealed[:-32], sealed[-32:]
        pt = receiver.open(b"message", ct, tag)
        self.assertEqual(pt, b"hello, world!")

        sender_confirm = sender.derive(b"confirm", 32)
        receiver_confirm = receiver.derive(b"confirm", 32)
        self.assertEqual(sender_confirm, receiver_confirm)

    def test_open_tampered_16_8(self):
        """§16.8: Open with tampered ciphertext returns None."""
        sender = Protocol()
        sender.init(b"test.vector")
        sender.mix(b"key", b"test-key-material")
        sender.mix(b"nonce", b"test-nonce-value")
        sealed = sender.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), "6e73c8fb8e615ac7d3bfdeaaa7e8e1af189b97db42b2870b693c5faf0be6bbc8345d8830401a53acccc756500a")

        receiver = Protocol()
        receiver.init(b"test.vector")
        receiver.mix(b"key", b"test-key-material")
        receiver.mix(b"nonce", b"test-nonce-value")
        tampered = bytearray(sealed)
        tampered[0] ^= 0xFF
        ct, tag = bytes(tampered[:-32]), bytes(tampered[-32:])
        pt = receiver.open(b"message", ct, tag)
        self.assertIsNone(pt)

        sender_out = sender.derive(b"after", 32)
        receiver_out = receiver.derive(b"after", 32)
        self.assertNotEqual(sender_out, receiver_out)

    def test_multiple_seals_16_9(self):
        """§16.9: Multiple Seals in sequence."""
        p = Protocol()
        p.init(b"test.vector")
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        s1 = p.seal(b"msg", b"first message")
        self.assertEqual(s1.hex(), "f58f5895735ec5679a75651160f0e2b29ea495e5a13e482d22c5bd1f58c75a345a9dacbf4205022b27f809fcc2")
        s2 = p.seal(b"msg", b"second message")
        self.assertEqual(s2.hex(), "2b6b64822aa4ac6716aaf6226e20d4d9f1c6ac6bafbe00761b03663b3e574d91be5fa8918945fa311214cfa83e1b")
        s3 = p.seal(b"msg", b"third message")
        self.assertEqual(s3.hex(), "86de20dad1084ed184d23aa56a3c3001a468b67c6687b2ab93e5b640008b6c912f88b6a3a88cd4283a7719c273")


import json
from pathlib import Path

VECTORS_PATH = Path(__file__).resolve().parent.parent / "docs" / "thyrse-test-vectors.json"


class TestVectorsJSON(unittest.TestCase):
    """Validate JSON test vectors against the reference implementation."""

    @classmethod
    def setUpClass(cls):
        with open(VECTORS_PATH) as f:
            cls.vectors = json.load(f)["vectors"]

    def _vec(self, vid):
        for v in self.vectors:
            if v["id"] == vid:
                return v
        self.fail(f"vector {vid} not found")

    def test_16_1_init_derive(self):
        vec = self._vec("12.1")
        p = Protocol()
        p.init(vec["init_label"].encode())
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), vec["expected"]["derive"])

    def test_16_2_mix_mix_derive(self):
        vec = self._vec("12.2")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), vec["expected"]["derive"])

    def test_16_3_seal_derive(self):
        vec = self._vec("12.3")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        sealed = p.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), vec["expected"]["seal"])
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), vec["expected"]["derive"])

    def test_16_4_mask_seal(self):
        vec = self._vec("12.4")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        masked = p.mask(b"unauthenticated", b"mask this data")
        self.assertEqual(masked.hex(), vec["expected"]["mask"])
        sealed = p.seal(b"authenticated", b"seal this data")
        self.assertEqual(sealed.hex(), vec["expected"]["seal"])

    def test_16_5_1_derive_no_ratchet(self):
        vec = self._vec("12.5.1")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), vec["expected"]["derive"])

    def test_16_5_2_ratchet_derive(self):
        vec = self._vec("12.5.2")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        p.ratchet(b"forward-secrecy")
        output = p.derive(b"output", 32)
        self.assertEqual(output.hex(), vec["expected"]["derive"])

    def test_16_6_fork(self):
        vec = self._vec("12.6")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        clones = p.fork(b"role", b"prover", b"verifier")
        self.assertEqual(p.derive(b"output", 32).hex(), vec["expected"]["base_derive"])
        self.assertEqual(clones[0].derive(b"output", 32).hex(), vec["expected"]["clone_1_derive"])
        self.assertEqual(clones[1].derive(b"output", 32).hex(), vec["expected"]["clone_2_derive"])

    def test_16_7_seal_open_roundtrip(self):
        vec = self._vec("12.7")
        sender = Protocol()
        sender.init(vec["init_label"].encode())
        sender.mix(b"key", b"test-key-material")
        sender.mix(b"nonce", b"test-nonce-value")
        sender.mix(b"ad", b"associated data")
        sealed = sender.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), vec["expected"]["seal"])

        receiver = Protocol()
        receiver.init(vec["init_label"].encode())
        receiver.mix(b"key", b"test-key-material")
        receiver.mix(b"nonce", b"test-nonce-value")
        receiver.mix(b"ad", b"associated data")
        ct, tag = sealed[:-32], sealed[-32:]
        pt = receiver.open(b"message", ct, tag)
        self.assertEqual(pt, b"hello, world!")

        self.assertEqual(sender.derive(b"confirm", 32), receiver.derive(b"confirm", 32))

    def test_16_8_seal_open_tampered(self):
        vec = self._vec("12.8")
        sender = Protocol()
        sender.init(vec["init_label"].encode())
        sender.mix(b"key", b"test-key-material")
        sender.mix(b"nonce", b"test-nonce-value")
        sealed = sender.seal(b"message", b"hello, world!")
        self.assertEqual(sealed.hex(), vec["expected"]["seal"])

        receiver = Protocol()
        receiver.init(vec["init_label"].encode())
        receiver.mix(b"key", b"test-key-material")
        receiver.mix(b"nonce", b"test-nonce-value")
        tampered = bytearray(sealed)
        tampered[0] ^= 0xFF
        ct, tag = bytes(tampered[:-32]), bytes(tampered[-32:])
        pt = receiver.open(b"message", ct, tag)
        self.assertIsNone(pt)

        self.assertNotEqual(sender.derive(b"after", 32), receiver.derive(b"after", 32))

    def test_16_9_1_seal(self):
        vec = self._vec("12.9.1")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        s1 = p.seal(b"msg", b"first message")
        self.assertEqual(s1.hex(), vec["expected"]["seal"])

    def test_16_9_2_seal(self):
        vec = self._vec("12.9.2")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        p.seal(b"msg", b"first message")
        s2 = p.seal(b"msg", b"second message")
        self.assertEqual(s2.hex(), vec["expected"]["seal"])

    def test_16_9_3_seal(self):
        vec = self._vec("12.9.3")
        p = Protocol()
        p.init(vec["init_label"].encode())
        p.mix(b"key", b"test-key-material")
        p.mix(b"nonce", b"test-nonce-value")
        p.seal(b"msg", b"first message")
        p.seal(b"msg", b"second message")
        s3 = p.seal(b"msg", b"third message")
        self.assertEqual(s3.hex(), vec["expected"]["seal"])
