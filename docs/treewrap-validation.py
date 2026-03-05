#!/usr/bin/env python3
"""TreeWrap spec vector utility.

Modes:
- --validate: validate reference implementation against JSON vectors.
- --update: recompute JSON expected values from reference implementation.
- --render: rewrite Section 9 in treewrap-spec.md from JSON vectors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SPEC_PATH = HERE / "treewrap-spec.md"
VECTORS_PATH = HERE / "treewrap-test-vectors.json"


def extract_python_blocks(markdown: str) -> list[str]:
    return re.findall(r"```python\n(.*?)\n```", markdown, flags=re.DOTALL)


def load_spec_namespace(spec_path: Path) -> dict[str, Any]:
    ns: dict[str, Any] = {}
    content = spec_path.read_text(encoding="utf-8")
    blocks = extract_python_blocks(content)
    if not blocks:
        raise RuntimeError(f"No Python code blocks found in {spec_path}")

    for i, block in enumerate(blocks, start=1):
        code = compile(block, f"{spec_path.name}:python-block-{i}", "exec")
        exec(code, ns, ns)

    required = [
        "encrypt_and_mac",
        "decrypt_and_mac",
        "treewrap128_encrypt",
        "treewrap128_decrypt",
        "TAU",
        "B",
    ]
    missing = [name for name in required if name not in ns]
    if missing:
        raise RuntimeError(f"Missing required definitions from spec blocks: {', '.join(missing)}")

    return ns


def load_vectors(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_vectors(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def bytes_from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def hx(b: bytes) -> str:
    return b.hex()


def make_message(msg_def: dict[str, Any]) -> bytes:
    mode = msg_def.get("mode")
    if mode == "seq_mod256":
        n = int(msg_def["len"])
        return bytes(i % 256 for i in range(n))
    if mode == "hex":
        return bytes_from_hex(msg_def.get("hex", ""))
    raise ValueError(f"Unsupported message mode: {mode}")


def is_incrementing_seq(data: bytes) -> bool:
    if len(data) < 2:
        return True
    for i in range(1, len(data)):
        if data[i] != (data[i - 1] + 1) % 256:
            return False
    return True


def fmt_bytes_short(data: bytes) -> str:
    if len(data) == 0:
        return "(empty)"
    if is_incrementing_seq(data) and len(data) >= 4:
        return f"{data[0]:02x} {data[1]:02x} {data[2]:02x} ... {data[-1]:02x}"
    if len(data) <= 16:
        return " ".join(f"{b:02x}" for b in data)
    return f"{data[:3].hex(' ')} ... {data[-1]:02x}"


def compute_bare_expected(ns: dict[str, Any], key: bytes, case: dict[str, Any]) -> dict[str, str]:
    enc = ns["encrypt_and_mac"]
    dec = ns["decrypt_and_mac"]
    bsz = int(ns["B"])

    msg = make_message(case["message"])
    ct, tag = enc(key, msg)

    out: dict[str, str] = {
        "tag_hex": hx(tag),
    }
    if len(ct) <= 32:
        out["ct_hex"] = hx(ct)
    else:
        out["ct_prefix32_hex"] = hx(ct[:32])

    mut = case.get("mutations", {})
    if mut.get("flip_first_bit") and len(ct) > 0:
        m = bytearray(ct)
        m[0] ^= 0x01
        _, mt = dec(key, bytes(m))
        out["flip_tag_hex"] = hx(mt)

    if mut.get("swap_chunk_0_1") and len(ct) >= 2 * bsz:
        m = bytearray(ct)
        c0 = bytes(m[:bsz])
        c1 = bytes(m[bsz : 2 * bsz])
        m[:bsz] = c1
        m[bsz : 2 * bsz] = c0
        _, mt = dec(key, bytes(m))
        out["swap_tag_hex"] = hx(mt)

    return out


def compute_aead_expected(ns: dict[str, Any], case: dict[str, Any]) -> dict[str, str]:
    enc = ns["treewrap128_encrypt"]
    tau = int(ns["TAU"])

    key = bytes_from_hex(case["key_hex"])
    nonce = bytes_from_hex(case["nonce_hex"])
    ad = bytes_from_hex(case["ad_hex"])
    msg = make_message(case["message"])

    ct_tag = enc(key, nonce, ad, msg)
    ct, tag = ct_tag[:-tau], ct_tag[-tau:]

    out: dict[str, str] = {}
    if len(ct_tag) <= 160:
        out["ct_tag_hex"] = hx(ct_tag)
    else:
        out["ct_prefix32_hex"] = hx(ct[:32])
        out["tag_hex"] = hx(tag)

    checks = case.get("checks", {})
    if checks.get("nonce_reuse_xor_leak"):
        alt_msg = make_message(case["alt_message"])
        alt_ct_tag = enc(key, nonce, ad, alt_msg)
        out["reuse_ct_tag_hex"] = hx(alt_ct_tag)

    if checks.get("swap_nonce_ad"):
        swapped_ct_tag = enc(key, ad, nonce, msg)
        out["swap_nonce_ad_ct_tag_hex"] = hx(swapped_ct_tag)

    if checks.get("ad_empty_vs_zero_byte"):
        alt_ad = bytes_from_hex(case.get("alt_ad_hex", "00"))
        alt_ct_tag = enc(key, nonce, alt_ad, msg)
        out["alt_ad_ct_tag_hex"] = hx(alt_ct_tag)

    return out


def validate_bare_case(ns: dict[str, Any], key: bytes, case: dict[str, Any], failures: list[str]) -> None:
    enc = ns["encrypt_and_mac"]
    dec = ns["decrypt_and_mac"]
    bsz = int(ns["B"])

    cid = case["id"]
    msg = make_message(case["message"])
    exp = case["expected"]

    ct, tag = enc(key, msg)
    pt2, tag2 = dec(key, ct)
    if pt2 != msg:
        failures.append(f"{cid}: round-trip plaintext mismatch")
    if tag2 != tag:
        failures.append(f"{cid}: round-trip tag mismatch")

    if "ct_hex" in exp and hx(ct) != exp["ct_hex"]:
        failures.append(f"{cid}: ct mismatch")
    if "ct_prefix32_hex" in exp and hx(ct[:32]) != exp["ct_prefix32_hex"]:
        failures.append(f"{cid}: ct_prefix32 mismatch")
    if hx(tag) != exp["tag_hex"]:
        failures.append(f"{cid}: tag mismatch")

    mut = case.get("mutations", {})
    if mut.get("flip_first_bit"):
        m = bytearray(ct)
        m[0] ^= 0x01
        _, mt = dec(key, bytes(m))
        if hx(mt) != exp.get("flip_tag_hex", ""):
            failures.append(f"{cid}: flip_tag mismatch")

    if mut.get("swap_chunk_0_1"):
        m = bytearray(ct)
        c0 = bytes(m[:bsz])
        c1 = bytes(m[bsz : 2 * bsz])
        m[:bsz] = c1
        m[bsz : 2 * bsz] = c0
        _, mt = dec(key, bytes(m))
        if hx(mt) != exp.get("swap_tag_hex", ""):
            failures.append(f"{cid}: swap_tag mismatch")


def validate_aead_case(ns: dict[str, Any], case: dict[str, Any], failures: list[str]) -> None:
    enc = ns["treewrap128_encrypt"]
    dec = ns["treewrap128_decrypt"]
    tau = int(ns["TAU"])

    cid = case["id"]
    key = bytes_from_hex(case["key_hex"])
    nonce = bytes_from_hex(case["nonce_hex"])
    ad = bytes_from_hex(case["ad_hex"])
    msg = make_message(case["message"])
    exp = case["expected"]

    ct_tag = enc(key, nonce, ad, msg)
    if dec(key, nonce, ad, ct_tag) != msg:
        failures.append(f"{cid}: round-trip mismatch")

    if "ct_tag_hex" in exp and hx(ct_tag) != exp["ct_tag_hex"]:
        failures.append(f"{cid}: ct||tag mismatch")

    ct, tag = ct_tag[:-tau], ct_tag[-tau:]
    if "ct_prefix32_hex" in exp and hx(ct[:32]) != exp["ct_prefix32_hex"]:
        failures.append(f"{cid}: ct_prefix32 mismatch")
    if "tag_hex" in exp and hx(tag) != exp["tag_hex"]:
        failures.append(f"{cid}: tag mismatch")

    checks = case.get("checks", {})
    if checks.get("bad_nonce"):
        bad_nonce = bytes([nonce[0] ^ 0x01]) + nonce[1:]
        if dec(key, bad_nonce, ad, ct_tag) is not None:
            failures.append(f"{cid}: bad nonce accepted")
    if checks.get("bad_ad"):
        if dec(key, nonce, ad + b"\x01", ct_tag) is not None:
            failures.append(f"{cid}: bad AD accepted")
    if checks.get("bad_tag"):
        bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]
        if dec(key, nonce, ad, ct + bad_tag) is not None:
            failures.append(f"{cid}: bad tag accepted")

    if checks.get("nonce_reuse_xor_leak"):
        alt_msg = make_message(case["alt_message"])
        alt_ct_tag = enc(key, nonce, ad, alt_msg)
        if hx(alt_ct_tag) != exp.get("reuse_ct_tag_hex", ""):
            failures.append(f"{cid}: reuse_ct_tag mismatch")
        if dec(key, nonce, ad, alt_ct_tag) != alt_msg:
            failures.append(f"{cid}: reused nonce alt round-trip mismatch")
        alt_ct = alt_ct_tag[:-tau]
        if len(alt_ct) != len(ct) or len(alt_msg) != len(msg):
            failures.append(f"{cid}: nonce reuse xor precondition length mismatch")
        else:
            xor_ct = bytes(a ^ b for a, b in zip(ct, alt_ct))
            xor_msg = bytes(a ^ b for a, b in zip(msg, alt_msg))
            if xor_ct != xor_msg:
                failures.append(f"{cid}: nonce reuse xor relation mismatch")

    if checks.get("swap_nonce_ad"):
        if len(ad) != len(nonce):
            failures.append(f"{cid}: swap_nonce_ad requires |AD| == |N|")
        else:
            swapped_ct_tag = enc(key, ad, nonce, msg)
            if hx(swapped_ct_tag) != exp.get("swap_nonce_ad_ct_tag_hex", ""):
                failures.append(f"{cid}: swap_nonce_ad_ct_tag mismatch")
            if swapped_ct_tag == ct_tag:
                failures.append(f"{cid}: swapping nonce/ad produced identical ct||tag")
            if dec(key, ad, nonce, ct_tag) is not None:
                failures.append(f"{cid}: swapping nonce/ad accepted original ct||tag")

    if checks.get("ad_empty_vs_zero_byte"):
        alt_ad = bytes_from_hex(case.get("alt_ad_hex", "00"))
        alt_ct_tag = enc(key, nonce, alt_ad, msg)
        if hx(alt_ct_tag) != exp.get("alt_ad_ct_tag_hex", ""):
            failures.append(f"{cid}: alt_ad_ct_tag mismatch")
        if alt_ct_tag == ct_tag:
            failures.append(f"{cid}: empty AD and alternate AD produced identical ct||tag")
        if dec(key, nonce, alt_ad, ct_tag) is not None:
            failures.append(f"{cid}: alternate AD accepted original ct||tag")
        if dec(key, nonce, alt_ad, alt_ct_tag) != msg:
            failures.append(f"{cid}: alternate AD round-trip mismatch")


def update_vectors(ns: dict[str, Any], vectors: dict[str, Any]) -> dict[str, Any]:
    bare_key = bytes_from_hex(vectors["bare"]["key_hex"])
    for case in vectors["bare"]["vectors"]:
        case["expected"] = compute_bare_expected(ns, bare_key, case)
    for case in vectors["aead"]["vectors"]:
        case["expected"] = compute_aead_expected(ns, case)
    return vectors


def validate_vectors(ns: dict[str, Any], vectors: dict[str, Any]) -> int:
    failures: list[str] = []

    bare_key = bytes_from_hex(vectors["bare"]["key_hex"])
    for case in vectors["bare"]["vectors"]:
        validate_bare_case(ns, bare_key, case, failures)

    for case in vectors["aead"]["vectors"]:
        validate_aead_case(ns, case, failures)

    if failures:
        print("VALIDATION FAILED")
        for f in failures:
            print(f"- {f}")
        return 1

    print("All JSON vectors validated successfully.")
    return 0


def render_section_9(vectors: dict[str, Any]) -> str:
    bare = vectors["bare"]
    aead = vectors["aead"]
    lines: list[str] = []

    lines.append("## 9. Test Vectors")
    lines.append("")

    lines.append("### 9.1 Internal Function Vectors")
    lines.append("")

    key = bytes_from_hex(bare["key_hex"])
    lines.append("All internal function vectors use:")
    lines.append("")
    lines.append(f"- **Key:** 32 bytes `{fmt_bytes_short(key)}`")
    lines.append("- **Plaintext:** `len` bytes `00 01 02 ... (len-1) mod 256`")
    lines.append("")
    lines.append("Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.")
    lines.append("")

    for case in bare["vectors"]:
        cid = case["id"]
        # Renumber: 9.1 -> 9.1.1, 9.2 -> 9.1.2, etc.
        old_num = cid.split(" ")[0]  # e.g. "9.1"
        sub = old_num.split(".")[1]  # e.g. "1"
        new_id = f"9.1.{sub}"
        title = case["title"]
        msg = make_message(case["message"])
        exp = case["expected"]

        lines.append(f"#### {new_id} {title}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| len | {len(msg)} |")
        if "ct_hex" in exp:
            lines.append(f"| ct | {( '`' + exp['ct_hex'] + '`') if exp['ct_hex'] else '(empty)'} |")
        else:
            lines.append(f"| ct[:32] | `{exp['ct_prefix32_hex']}` |")
        lines.append(f"| tag | `{exp['tag_hex']}` |")
        lines.append("")

        if "flip_tag_hex" in exp:
            if len(msg) == 1:
                lines.append("Flipping bit 0 of the ciphertext (`f0`) yields tag")
            else:
                lines.append("Flipping bit 0 of `ct[0]` yields tag")
            lines.append(f"`{exp['flip_tag_hex']}`.")
            lines.append("")

        if "swap_tag_hex" in exp:
            lines.append("Swapping chunks 0 and 1 (bytes 0-8,191 and 8,192-16,383) yields tag")
            lines.append(f"`{exp['swap_tag_hex']}`.")
            lines.append("")

    lines.append("#### 9.1.6 Round-Trip Consistency")
    lines.append("")
    lines.append("For all internal function vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as")
    lines.append("`EncryptAndMAC`.")
    lines.append("")

    lines.append("### 9.2 TreeWrap128 Vectors")
    lines.append("")
    lines.append("These vectors validate `treewrap128_encrypt` / `treewrap128_decrypt`, including SP 800-185")
    lines.append("`encode_string` key derivation.")
    lines.append("")

    for case in aead["vectors"]:
        cid = case["id"]
        # Renumber: 9.7.1 -> 9.2.1, 9.7.2 -> 9.2.2, etc.
        old_num = cid.split(" ")[0]  # e.g. "9.7.1"
        sub = old_num.split(".")[2]  # e.g. "1"
        new_id = f"9.2.{sub}"
        title = case["title"]
        key = bytes_from_hex(case["key_hex"])
        nonce = bytes_from_hex(case["nonce_hex"])
        ad = bytes_from_hex(case["ad_hex"])
        msg = make_message(case["message"])
        exp = case["expected"]

        lines.append(f"#### {new_id} {title}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| K | {len(key)} bytes `{fmt_bytes_short(key)}` |")
        lines.append(f"| N | {len(nonce)} bytes `{fmt_bytes_short(nonce)}` |")
        lines.append(f"| AD | {fmt_bytes_short(ad) if len(ad) else '(empty)'} |")
        if case["message"]["mode"] == "seq_mod256" and len(msg) > 32:
            lines.append(f"| M len | {len(msg)} (`00 01 02 ... mod 256`) |")
        elif case["message"]["mode"] == "seq_mod256":
            lines.append(f"| M len | {len(msg)} (`00 01 02 ... {msg[-1]:02x}`) |" if len(msg) else "| M len | 0 |")
        else:
            lines.append(f"| M len | {len(msg)} |")

        if "ct_tag_hex" in exp:
            lines.append(f"| ct‖tag | `{exp['ct_tag_hex']}` |")
        else:
            lines.append(f"| ct[:32] | `{exp['ct_prefix32_hex']}` |")
            lines.append(f"| tag | `{exp['tag_hex']}` |")
        lines.append("")
        lines.append("`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.")
        lines.append("Changing `N`, `AD`, or `tag` causes decryption to return `None`.")
        checks = case.get("checks", {})
        if checks.get("nonce_reuse_xor_leak"):
            lines.append("Reusing the same `(K, N, AD)` with a different message is deterministic and yields")
            lines.append("`ct1 xor ct2 = m1 xor m2` for equal-length messages (validated by this vector).")
            lines.append("Nonce reuse is out of scope for Section 6 nonce-respecting claims.")
        if checks.get("swap_nonce_ad"):
            lines.append("Swapping `N` and `AD` (same byte length) yields a different `ct‖tag` and does not")
            lines.append("validate the original `ct‖tag`.")
        if checks.get("ad_empty_vs_zero_byte"):
            lines.append("Empty AD and one-byte AD `00` are distinct contexts and produce different `ct‖tag`.")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_spec(spec_path: Path, vectors: dict[str, Any]) -> None:
    md = spec_path.read_text(encoding="utf-8")
    start = md.find("## 9. Test Vectors")
    end = md.find("## Appendix A.")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("Could not locate Section 9 / Appendix A boundaries in spec")

    new_sec9 = render_section_9(vectors)
    updated = md[:start] + new_sec9 + "\n" + md[end:]
    spec_path.write_text(updated, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="TreeWrap spec vector utility")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--validate", action="store_true", help="validate JSON vectors against spec reference implementation")
    g.add_argument("--update", action="store_true", help="update JSON expected values from spec reference implementation")
    g.add_argument("--render", action="store_true", help="render Section 9 in spec from JSON vectors")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if not SPEC_PATH.exists():
        print(f"Spec file not found: {SPEC_PATH}", file=sys.stderr)
        return 2
    if not VECTORS_PATH.exists():
        print(f"Vector JSON not found: {VECTORS_PATH}", file=sys.stderr)
        return 2

    try:
        ns = load_spec_namespace(SPEC_PATH)
        vectors = load_vectors(VECTORS_PATH)

        if args.update:
            vectors = update_vectors(ns, vectors)
            save_vectors(VECTORS_PATH, vectors)
            print(f"Updated vector JSON: {VECTORS_PATH}")
            return 0

        if args.validate:
            return validate_vectors(ns, vectors)

        if args.render:
            render_spec(SPEC_PATH, vectors)
            print(f"Rendered Section 9 from JSON into: {SPEC_PATH}")
            return 0

        return 2
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
