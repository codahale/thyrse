#!/usr/bin/env python3
"""Validate TreeWrap Section 9 vectors from docs/treewrap-spec.md.

This script:
1) extracts all Python code blocks from the spec,
2) executes them in order,
3) produces and verifies the vectors described in Section 9.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def extract_python_blocks(markdown: str) -> list[str]:
    return re.findall(r"```python\n(.*?)\n```", markdown, flags=re.DOTALL)


def extract_section9_vectors(markdown: str) -> dict[str, dict[str, str | int]]:
    expected: dict[str, dict[str, str | int]] = {}
    section_pattern = re.compile(
        r"###\s+(9\.[1-5])\b.*?\n(.*?)(?=\n###\s+9\.[1-6]\b|\n##\s+Appendix|\Z)",
        flags=re.DOTALL,
    )
    row_pattern = re.compile(r"^\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*$", flags=re.MULTILINE)

    for sec, body in section_pattern.findall(markdown):
        data: dict[str, str | int] = {}

        rows = {k.strip(): v.strip() for k, v in row_pattern.findall(body)}
        if "len" in rows:
            data["len"] = int(rows["len"])
        if "ct" in rows:
            ct = rows["ct"].strip("`")
            data["ct"] = "" if ct == "(empty)" else ct
        if "ct[:32]" in rows:
            data["ct_prefix"] = rows["ct[:32]"].strip("`")
        if "tag" in rows:
            data["tag"] = rows["tag"].strip("`")

        m_flip = re.search(r"Flipping bit 0 .*? yields tag\s*`([0-9a-f]+)`", body, flags=re.DOTALL)
        if m_flip:
            data["flip_tag"] = m_flip.group(1)

        m_swap = re.search(r"Swapping chunks .*? yields tag\s*`([0-9a-f]+)`", body, flags=re.DOTALL)
        if m_swap:
            data["swap_tag"] = m_swap.group(1)

        expected[sec] = data

    required_sections = ("9.1", "9.2", "9.3", "9.4", "9.5")
    missing_sections = [s for s in required_sections if s not in expected]
    if missing_sections:
        raise RuntimeError(f"Missing Section 9 vectors in spec: {', '.join(missing_sections)}")

    return expected


def load_spec_namespace(spec_path: Path) -> dict:
    ns: dict = {}
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
    ]
    missing = [name for name in required if name not in ns]
    if missing:
        raise RuntimeError(f"Missing required definitions from spec blocks: {', '.join(missing)}")

    return ns


def make_plaintext(length: int) -> bytes:
    return bytes(i % 256 for i in range(length))


def hx(b: bytes) -> str:
    return b.hex()


def check_equal(name: str, got: str, expected: str, failures: list[str]) -> None:
    if got != expected:
        failures.append(f"{name}: got {got}, expected {expected}")


def run_validation(ns: dict, expected: dict[str, dict[str, str | int]]) -> int:
    encrypt_and_mac = ns["encrypt_and_mac"]
    decrypt_and_mac = ns["decrypt_and_mac"]

    key = bytes(range(32))
    failures: list[str] = []

    # Produce + verify vectors 9.1-9.5.
    for section in ("9.1", "9.2", "9.3", "9.4", "9.5"):
        exp = expected[section]
        length = int(exp["len"])
        pt = make_plaintext(length)

        ct, tag = encrypt_and_mac(key, pt)
        pt2, tag2 = decrypt_and_mac(key, ct)

        # 9.6 round-trip consistency for all listed vectors.
        if pt2 != pt:
            failures.append(f"{section} round-trip plaintext mismatch")
        if tag2 != tag:
            failures.append(f"{section} round-trip tag mismatch")

        if "ct" in exp:
            check_equal(f"{section} ct", hx(ct), str(exp["ct"]), failures)
        if "ct_prefix" in exp:
            check_equal(f"{section} ct_prefix", hx(ct[:32]), str(exp["ct_prefix"]), failures)
        check_equal(f"{section} tag", hx(tag), str(exp["tag"]), failures)

        # Mutation checks.
        if "flip_tag" in exp and len(ct) > 0:
            ct_flip = bytearray(ct)
            ct_flip[0] ^= 0x01
            _, tag_flip = decrypt_and_mac(key, bytes(ct_flip))
            check_equal(f"{section} flip_tag", hx(tag_flip), str(exp["flip_tag"]), failures)

        if section == "9.5":
            b = ns.get("B", 8192)
            ct_swap = bytearray(ct)
            c0 = bytes(ct_swap[:b])
            c1 = bytes(ct_swap[b : 2 * b])
            ct_swap[:b] = c1
            ct_swap[b : 2 * b] = c0
            _, tag_swap = decrypt_and_mac(key, bytes(ct_swap))
            check_equal(f"{section} swap_tag", hx(tag_swap), str(exp["swap_tag"]), failures)

        # Produce output for easy regeneration/copying.
        print(f"{section}: len={length}")
        if len(ct) == 0:
            print("  ct: (empty)")
        elif len(ct) <= 32:
            print(f"  ct: {hx(ct)}")
        else:
            print(f"  ct[:32]: {hx(ct[:32])}")
        print(f"  tag: {hx(tag)}")

    if failures:
        print("\nVALIDATION FAILED")
        for f in failures:
            print(f"- {f}")
        return 1

    print("\nAll Section 9 vectors validated successfully.")
    return 0


def main() -> int:
    spec_path = Path(__file__).with_name("treewrap-spec.md")
    if not spec_path.exists():
        print(f"Spec file not found: {spec_path}", file=sys.stderr)
        return 2

    try:
        content = spec_path.read_text(encoding="utf-8")
        expected = extract_section9_vectors(content)
        ns = load_spec_namespace(spec_path)
        return run_validation(ns, expected)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
