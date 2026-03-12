"""Test TW128 AEAD mode against the canonical test vectors."""

import json
import unittest
from pathlib import Path

from .tw128 import tw128_encrypt, tw128_decrypt, TAU

VECTORS_PATH = Path(__file__).resolve().parent.parent / "docs" / "tw128-test-vectors.json"


def make_message(msg_def):
    mode = msg_def.get("mode")
    if mode == "seq_mod256":
        n = int(msg_def["len"])
        return bytes(i % 256 for i in range(n))
    if mode == "hex":
        return bytes.fromhex(msg_def.get("hex", ""))
    raise ValueError(f"Unsupported message mode: {mode}")


class TestAEADVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(VECTORS_PATH) as f:
            doc = json.load(f)
        cls.vectors = doc["aead"]["vectors"]

    def test_vectors(self):
        for case in self.vectors:
            with self.subTest(id=case["id"]):
                key = bytes.fromhex(case["key_hex"])
                nonce = bytes.fromhex(case["nonce_hex"])
                ad = bytes.fromhex(case["ad_hex"])
                msg = make_message(case["message"])
                exp = case["expected"]
                checks = case.get("checks", {})

                ct_tag = tw128_encrypt(key, nonce, ad, msg)
                ct, tag = ct_tag[:-TAU], ct_tag[-TAU:]

                if "ct_tag_hex" in exp:
                    self.assertEqual(ct_tag.hex(), exp["ct_tag_hex"])
                if "ct_prefix32_hex" in exp:
                    self.assertEqual(ct[:32].hex(), exp["ct_prefix32_hex"])
                if "tag_hex" in exp:
                    self.assertEqual(tag.hex(), exp["tag_hex"])

                # Round-trip
                pt = tw128_decrypt(key, nonce, ad, ct_tag)
                self.assertEqual(pt, msg)

                # Bad nonce
                if checks.get("bad_nonce"):
                    bad_nonce = bytearray(nonce)
                    bad_nonce[0] ^= 0x01
                    self.assertIsNone(tw128_decrypt(key, bytes(bad_nonce), ad, ct_tag))

                # Bad AD
                if checks.get("bad_ad"):
                    self.assertIsNone(tw128_decrypt(key, nonce, ad + b"\x01", ct_tag))

                # Bad tag
                if checks.get("bad_tag"):
                    bad_ct_tag = bytearray(ct_tag)
                    bad_ct_tag[-TAU] ^= 0x01
                    self.assertIsNone(tw128_decrypt(key, nonce, ad, bytes(bad_ct_tag)))

                # Nonce reuse XOR leak
                if checks.get("nonce_reuse_xor_leak"):
                    alt_msg = make_message(case["alt_message"])
                    reuse_ct_tag = tw128_encrypt(key, nonce, ad, alt_msg)
                    self.assertEqual(reuse_ct_tag.hex(), exp["reuse_ct_tag_hex"])
                    ct1 = ct_tag[:-TAU]
                    ct2 = reuse_ct_tag[:-TAU]
                    xor_ct = bytes(a ^ b for a, b in zip(ct1, ct2))
                    xor_msg = bytes(a ^ b for a, b in zip(msg, alt_msg))
                    self.assertEqual(xor_ct, xor_msg)

                # Swap nonce and AD
                if checks.get("swap_nonce_ad"):
                    swap_ct_tag = tw128_encrypt(key, ad, nonce, msg)
                    self.assertEqual(swap_ct_tag.hex(), exp["swap_nonce_ad_ct_tag_hex"])
                    self.assertNotEqual(swap_ct_tag, ct_tag)
                    # Original ct_tag rejected with swapped nonce/ad
                    self.assertIsNone(tw128_decrypt(key, ad, nonce, ct_tag))

                # AD empty vs zero byte
                if checks.get("ad_empty_vs_zero_byte"):
                    alt_ad = bytes.fromhex(case["alt_ad_hex"])
                    alt_ct_tag = tw128_encrypt(key, nonce, alt_ad, msg)
                    self.assertEqual(alt_ct_tag.hex(), exp["alt_ad_ct_tag_hex"])
                    self.assertNotEqual(alt_ct_tag, ct_tag)
                    # Cross-rejection
                    self.assertIsNone(tw128_decrypt(key, nonce, alt_ad, ct_tag))
                    self.assertIsNone(tw128_decrypt(key, nonce, ad, alt_ct_tag))
                    # Alt round-trip
                    self.assertEqual(tw128_decrypt(key, nonce, alt_ad, alt_ct_tag), msg)


if __name__ == "__main__":
    unittest.main()
