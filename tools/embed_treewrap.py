#!/usr/bin/env python3
"""Embed ref/ code snippets and vector tables into TreeWrap spec Markdown."""

import json
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def extract_function(source: str, name: str) -> str:
    """Extract a top-level function definition by name."""
    lines = source.split("\n")
    start = None
    prefix = f"def {name}("
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            start = i
            break
    if start is None:
        raise ValueError(f"function {name!r} not found")
    # Collect the function body: stop at the next top-level definition or
    # non-blank, non-comment line at column 0.
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line or line[0] == " " or line[0] == "\t" or line.lstrip().startswith("#"):
            continue
        # Non-blank, non-indented, non-comment line -> new top-level entity
        end = i
        break
    # Strip trailing blank lines
    result_lines = lines[start:end]
    while result_lines and result_lines[-1].strip() == "":
        result_lines.pop()
    return "\n".join(result_lines)


def extract_region(source: str, name: str) -> str:
    """Extract content between # region: name and # endregion markers."""
    lines = source.split("\n")
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"# region: {name}":
            start = i + 1
            break
    if start is None:
        raise ValueError(f"region {name!r} not found")
    end = None
    for i in range(start, len(lines)):
        if lines[i].strip() == "# endregion":
            end = i
            break
    if end is None:
        raise ValueError(f"endregion for {name!r} not found")
    result_lines = lines[start:end]
    # Strip leading/trailing blank lines
    while result_lines and result_lines[0].strip() == "":
        result_lines.pop(0)
    while result_lines and result_lines[-1].strip() == "":
        result_lines.pop()
    return "\n".join(result_lines)


def extract_snippet(file_path: Path, name: str) -> str:
    """Try function extraction first, fall back to region extraction."""
    source = file_path.read_text()
    try:
        return extract_function(source, name)
    except ValueError:
        return extract_region(source, name)


CODE_MARKER = re.compile(
    r"(<!-- begin:code:(\S+):(\S+) -->)\n"
    r".*?"
    r"(<!-- end:code:\2:\3 -->)",
    re.DOTALL,
)


def replace_code_markers(md: str) -> str:
    def replacer(m):
        begin_tag = m.group(1)
        file_rel = m.group(2)
        name = m.group(3)
        end_tag = m.group(4)
        file_path = PROJECT_ROOT / file_rel
        snippet = extract_snippet(file_path, name)
        return f"{begin_tag}\n```python\n{snippet}\n```\n{end_tag}"
    return CODE_MARKER.sub(replacer, md)


def _fmt_bytes_short(data: bytes) -> str:
    """Format bytes for display: incrementing sequences get 'xx xx xx ... xx' format."""
    if len(data) == 0:
        return "(empty)"
    if len(data) >= 4 and all(data[i] == (data[i-1] + 1) % 256 for i in range(1, len(data))):
        return f"{data[0]:02x} {data[1]:02x} {data[2]:02x} ... {data[-1]:02x}"
    if len(data) <= 16:
        return " ".join(f"{b:02x}" for b in data)
    return f"{data[:3].hex(' ')} ... {data[-1]:02x}"


def _make_message(msg_def: dict) -> bytes:
    mode = msg_def.get("mode")
    if mode == "seq_mod256":
        return bytes(i % 256 for i in range(int(msg_def["len"])))
    if mode == "hex":
        return bytes.fromhex(msg_def.get("hex", ""))
    raise ValueError(f"Unsupported message mode: {mode}")


def render_bare_vectors(data: dict) -> str:
    """Render bare (internal function) vectors as Markdown matching spec §10.1."""
    bare = data["bare"]
    lines: list[str] = []

    lines.append("### 10.1 Internal Function Vectors")
    lines.append("")

    key = bytes.fromhex(bare["key_hex"])
    lines.append("All internal function vectors use:")
    lines.append("")
    lines.append(f"- **Key:** 32 bytes `{_fmt_bytes_short(key)}`")
    lines.append("- **Plaintext:** `len` bytes `00 01 02 ... (len-1) mod 256`")
    lines.append("")
    lines.append("Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.")
    lines.append("")

    for case in bare["vectors"]:
        cid = case["id"]
        title = case["title"]
        msg = _make_message(case["message"])
        exp = case["expected"]

        lines.append(f"#### {cid} {title}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| len | {len(msg)} |")
        if "ct_hex" in exp:
            lines.append(f"| ct | {('`' + exp['ct_hex'] + '`') if exp['ct_hex'] else '(empty)'} |")
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
            lines.append("Swapping chunks 1 and 2 (bytes 0\u20138,191 and 8,192\u201316,383) yields tag")
            lines.append(f"`{exp['swap_tag_hex']}`.")
            lines.append("")

    lines.append("#### 10.1.6 Round-Trip Consistency")
    lines.append("")
    lines.append("For all internal function vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as")
    lines.append("`EncryptAndMAC`.")

    return "\n".join(lines)


def render_aead_vectors(data: dict) -> str:
    """Render AEAD vectors as Markdown matching spec §10.2."""
    aead = data["aead"]
    lines: list[str] = []

    lines.append("### 10.2 TreeWrap128 Vectors")
    lines.append("")
    lines.append("These vectors validate `treewrap128_encrypt` / `treewrap128_decrypt`, including SP 800-185")
    lines.append("`encode_string` key derivation.")
    lines.append("")

    for case in aead["vectors"]:
        cid = case["id"]
        title = case["title"]
        key = bytes.fromhex(case["key_hex"])
        nonce = bytes.fromhex(case["nonce_hex"])
        ad = bytes.fromhex(case["ad_hex"])
        msg = _make_message(case["message"])
        exp = case["expected"]

        lines.append(f"#### {cid} {title}")
        lines.append("")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| K | {len(key)} bytes `{_fmt_bytes_short(key)}` |")
        lines.append(f"| N | {len(nonce)} bytes `{_fmt_bytes_short(nonce)}` |")
        lines.append(f"| AD | {_fmt_bytes_short(ad) if len(ad) else '(empty)'} |")
        if case["message"]["mode"] == "seq_mod256" and len(msg) > 32:
            lines.append(f"| M len | {len(msg)} (`00 01 02 ... mod 256`) |")
        elif case["message"]["mode"] == "seq_mod256":
            lines.append(f"| M len | {len(msg)} (`00 01 02 ... {msg[-1]:02x}`) |" if len(msg) else "| M len | 0 |")
        else:
            lines.append(f"| M len | {len(msg)} |")

        if "ct_tag_hex" in exp:
            lines.append(f"| ct\u2016tag | `{exp['ct_tag_hex']}` |")
        else:
            lines.append(f"| ct[:32] | `{exp['ct_prefix32_hex']}` |")
            lines.append(f"| tag | `{exp['tag_hex']}` |")
        lines.append("")
        lines.append("`treewrap128_decrypt(K, N, AD, ct\u2016tag)` returns the original plaintext.")
        lines.append("Changing `N`, `AD`, or `tag` causes decryption to return `None`.")
        checks = case.get("checks", {})
        if checks.get("nonce_reuse_xor_leak"):
            lines.append("Reusing the same `(K, N, AD)` with a different message is deterministic and yields")
            lines.append("`ct1 xor ct2 = m1 xor m2` within each rate block (168 bytes); overwrite mode causes")
            lines.append("keystream divergence at subsequent block boundaries (validated by this vector).")
            lines.append("Nonce reuse is out of scope for Section 6 nonce-respecting claims.")
        if checks.get("swap_nonce_ad"):
            lines.append("Swapping `N` and `AD` (same byte length) yields a different `ct\u2016tag` and does not")
            lines.append("validate the original `ct\u2016tag`.")
        if checks.get("ad_empty_vs_zero_byte"):
            lines.append("Empty AD and one-byte AD `00` are distinct contexts and produce different `ct\u2016tag`.")
        lines.append("")

    return "\n".join(lines).rstrip()


VECTORS_MARKER = re.compile(
    r"(<!-- begin:vectors:(\S+):(\S+) -->)\n"
    r".*?"
    r"(<!-- end:vectors:\2:\3 -->)",
    re.DOTALL,
)


def replace_vectors_markers(md: str) -> str:
    _cache: dict[str, dict] = {}

    def _load(path_rel: str) -> dict:
        if path_rel not in _cache:
            file_path = PROJECT_ROOT / path_rel
            _cache[path_rel] = json.loads(file_path.read_text(encoding="utf-8"))
        return _cache[path_rel]

    def replacer(m):
        begin_tag = m.group(1)
        file_rel = m.group(2)
        section = m.group(3)
        end_tag = m.group(4)
        data = _load(file_rel)
        if section == "bare":
            rendered = render_bare_vectors(data)
        elif section == "aead":
            rendered = render_aead_vectors(data)
        else:
            raise ValueError(f"Unknown vector section: {section!r}")
        return f"{begin_tag}\n{rendered}\n{end_tag}"

    return VECTORS_MARKER.sub(replacer, md)


def embed(spec_path: Path) -> None:
    md = spec_path.read_text()
    md = replace_code_markers(md)
    md = replace_vectors_markers(md)
    spec_path.write_text(md)
    print(f"Embedded: {spec_path}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <spec.md> [spec2.md ...]", file=sys.stderr)
        return 1
    for arg in sys.argv[1:]:
        embed(Path(arg))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
