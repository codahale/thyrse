"""Tests for Thyrse reference implementation."""

import unittest
from .encodings import right_encode


class TestRightEncode(unittest.TestCase):
    def test_spec_examples(self):
        """§4 examples: right_encode(0) = 0x00 0x01, right_encode(127) = 0x7F 0x01, right_encode(256) = 0x01 0x00 0x02."""
        self.assertEqual(right_encode(0), b"\x00\x01")
        self.assertEqual(right_encode(127), b"\x7f\x01")
        self.assertEqual(right_encode(256), b"\x01\x00\x02")
