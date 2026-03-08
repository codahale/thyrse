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
