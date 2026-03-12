#!/usr/bin/env python3
"""Recompute expected outputs in tw128-test-vectors.json from the ref/ package."""

import json
import sys
from pathlib import Path

# Add project root so `import ref` works regardless of cwd.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ref.tw128 import tw128_encrypt, TAU


def make_message(msg_def: dict) -> bytes:
    mode = msg_def.get("mode")
    if mode == "seq_mod256":
        return bytes(i % 256 for i in range(int(msg_def["len"])))
    if mode == "hex":
        return bytes.fromhex(msg_def.get("hex", ""))
    raise ValueError(f"Unsupported message mode: {mode}")


def update_aead(section: dict) -> None:
    for vec in section["vectors"]:
        key = bytes.fromhex(vec["key_hex"])
        nonce = bytes.fromhex(vec["nonce_hex"])
        ad = bytes.fromhex(vec["ad_hex"])
        msg = make_message(vec["message"])
        checks = vec.get("checks", {})

        ct_tag = tw128_encrypt(key, nonce, ad, msg)

        expected: dict = {}
        if len(ct_tag) <= 160:
            expected["ct_tag_hex"] = ct_tag.hex()
        else:
            expected["ct_prefix32_hex"] = ct_tag[:32].hex()
            expected["tag_hex"] = ct_tag[-TAU:].hex()

        if checks.get("nonce_reuse_xor_leak"):
            alt_msg = make_message(vec["alt_message"])
            reuse_ct_tag = tw128_encrypt(key, nonce, ad, alt_msg)
            expected["reuse_ct_tag_hex"] = reuse_ct_tag.hex()

        if checks.get("swap_nonce_ad"):
            swap_ct_tag = tw128_encrypt(key, ad, nonce, msg)
            expected["swap_nonce_ad_ct_tag_hex"] = swap_ct_tag.hex()

        if checks.get("ad_empty_vs_zero_byte"):
            alt_ad = bytes.fromhex(vec["alt_ad_hex"])
            alt_ad_ct_tag = tw128_encrypt(key, nonce, alt_ad, msg)
            expected["alt_ad_ct_tag_hex"] = alt_ad_ct_tag.hex()

        vec["expected"] = expected


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <vectors.json>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    data = json.loads(path.read_text())

    if "aead" in data:
        update_aead(data["aead"])

    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")
    print(f"Updated {path}")


if __name__ == "__main__":
    main()
