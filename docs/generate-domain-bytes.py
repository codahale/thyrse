#!/usr/bin/env python3
"""Generate Sakura-compliant domain bytes for TreeWrap128.

Encodes the following requirements:

1. Keccak delimited-suffix encoding:
   A suffix bit-string S of length L is stored in a byte as:
     - bits 0..L-1: suffix bits (leftmost/first bit → bit 0 = LSB)
     - bit L: delimiter '1'
     - bits L+1..7: zero
   This means byte = sum(S[i] * 2^i for i in 0..L-1) + 2^L.

2. TurboSHAKE domain byte constraint (RFC 9861):
     0x01 ≤ D ≤ 0x7F  (bit 7 = 0, D ≠ 0)
   Maximum suffix length is therefore 6 bits (delimiter at bit 6).

3. Sakura node typing (ePrint 2013/231):
   - Inner/leaf nodes: suffix ends with '0' (simple padding)
   - Final nodes: suffix ends with '1' (no simple padding)
   The last suffix bit (bit L-1) encodes the node type.

4. TreeWrap128 role assignments:
   - init            : inner (S_last=0) — key/index absorption in leaf cipher
   - chain_value     : inner (S_last=0) — final block of leaf for multi-chunk
   - KDF             : inner (S_last=0) — AEAD key derivation
   - single_node_tag : final (S_last=1) — single-node tag squeeze (n=1)
   - tag_accum       : final (S_last=1) — tag accumulation in final node

5. Reserved bytes to avoid (cross-protocol collision prevention):
   - 0x07: KangarooTwelve message-hop final / TurboSHAKE128 standard
   - 0x0B: KangarooTwelve message-hop inner
   - 0x06: KangarooTwelve chaining-hop final
   - 0x1F: SHAKE
   - 0x06: SHA-3
   - 0x04: RawSHAKE

6. All 5 domain bytes must be pairwise distinct.
"""

from itertools import product


# --- Encoding ---

def suffix_to_byte(suffix_bits: list[int]) -> int:
    """Encode a suffix bit-string into a Keccak delimited-suffix byte.

    suffix_bits[0] is the leftmost (first-written) suffix bit, stored at bit 0.
    The delimiter '1' is placed at bit len(suffix_bits).
    """
    L = len(suffix_bits)
    assert 1 <= L <= 6, f"Suffix length {L} out of range [1, 6]"
    assert all(b in (0, 1) for b in suffix_bits), "Suffix bits must be 0 or 1"
    byte_val = sum(bit << i for i, bit in enumerate(suffix_bits)) | (1 << L)
    assert 0x01 <= byte_val <= 0x7F, f"Byte 0x{byte_val:02X} out of TurboSHAKE range"
    return byte_val


def byte_to_suffix(byte_val: int) -> list[int]:
    """Decode a Keccak delimited-suffix byte back to suffix bits.

    Finds the highest set bit (delimiter), returns bits below it.
    """
    assert 0x01 <= byte_val <= 0x7F
    # Find delimiter: highest set bit
    L = byte_val.bit_length() - 1  # position of delimiter
    assert L >= 1, "Suffix must be at least 1 bit"
    suffix_bits = [(byte_val >> i) & 1 for i in range(L)]
    return suffix_bits


def suffix_to_str(suffix_bits: list[int]) -> str:
    """Format suffix bits as a readable string (leftmost first)."""
    return ''.join(str(b) for b in suffix_bits)


def is_inner(suffix_bits: list[int]) -> bool:
    """Inner node: last suffix bit is 0."""
    return suffix_bits[-1] == 0


def is_final(suffix_bits: list[int]) -> bool:
    """Final node: last suffix bit is 1."""
    return suffix_bits[-1] == 1


# --- Reserved bytes ---

RESERVED = {
    0x07: "K12 message-hop final / TurboSHAKE128",
    0x0B: "K12 message-hop inner",
    0x06: "K12 chaining-hop final / SHA-3",
    0x1F: "SHAKE",
    0x04: "RawSHAKE",
}


# --- Role definitions ---

ROLES = [
    ("init",            "inner", "Key/index absorption in leaf cipher"),
    ("chain_value",     "inner", "Final block of leaf for multi-chunk"),
    ("KDF",             "inner", "AEAD key derivation"),
    ("single_node_tag", "final", "Single-node tag squeeze (n=1)"),
    ("tag_accum",       "final", "Tag accumulation in final node"),
]


def generate_valid_bytes(node_type: str, max_suffix_len: int = 6) -> list[tuple[int, list[int]]]:
    """Generate all valid (byte, suffix) pairs for a given node type."""
    results = []
    for L in range(1, max_suffix_len + 1):
        for bits in product([0, 1], repeat=L):
            suffix = list(bits)
            # Check node type constraint
            if node_type == "inner" and not is_inner(suffix):
                continue
            if node_type == "final" and not is_final(suffix):
                continue
            byte_val = suffix_to_byte(suffix)
            # Check TurboSHAKE range (always true by construction, but verify)
            if not (0x01 <= byte_val <= 0x7F):
                continue
            # Check not reserved
            if byte_val in RESERVED:
                continue
            results.append((byte_val, suffix))
    return results


def verify_byte(byte_val: int, expected_type: str, role_name: str) -> list[str]:
    """Verify a domain byte meets all requirements. Returns list of errors."""
    errors = []
    if not (0x01 <= byte_val <= 0x7F):
        errors.append(f"0x{byte_val:02X}: outside TurboSHAKE range [0x01, 0x7F]")
    if byte_val in RESERVED:
        errors.append(f"0x{byte_val:02X}: collides with {RESERVED[byte_val]}")
    suffix = byte_to_suffix(byte_val)
    if expected_type == "inner" and not is_inner(suffix):
        errors.append(
            f"0x{byte_val:02X} ({role_name}): last suffix bit is {suffix[-1]}, "
            f"expected 0 for inner node"
        )
    if expected_type == "final" and not is_final(suffix):
        errors.append(
            f"0x{byte_val:02X} ({role_name}): last suffix bit is {suffix[-1]}, "
            f"expected 1 for final node"
        )
    return errors


def main():
    import sys

    # --- 1. Verify current (broken) assignments ---
    print("=" * 72)
    print("VERIFICATION OF CURRENT DOMAIN BYTES")
    print("=" * 72)
    current = {
        "init":            0x33,
        "chain_value":     0x2B,
        "KDF":             0x3B,
        "single_node_tag": 0x27,
        "tag_accum":       0x37,
    }
    all_errors = []
    for role_name, node_type, desc in ROLES:
        byte_val = current[role_name]
        suffix = byte_to_suffix(byte_val)
        errors = verify_byte(byte_val, node_type, role_name)
        status = "OK" if not errors else "FAIL"
        print(f"\n  {role_name:20s}: 0x{byte_val:02X} (suffix '{suffix_to_str(suffix)}', "
              f"len={len(suffix)}) [{status}]")
        if errors:
            for e in errors:
                print(f"    ERROR: {e}")
            all_errors.extend(errors)
        else:
            actual_type = "final" if is_final(suffix) else "inner"
            print(f"    Suffix last bit = {suffix[-1]} → {actual_type} ✓")

    if all_errors:
        print(f"\n  *** {len(all_errors)} error(s) found in current assignments ***")
    else:
        print("\n  All current assignments are valid.")

    # --- 2. Show all valid bytes per role ---
    print("\n" + "=" * 72)
    print("VALID DOMAIN BYTES PER ROLE")
    print("=" * 72)
    valid_per_role = {}
    for role_name, node_type, desc in ROLES:
        valid = generate_valid_bytes(node_type)
        valid_per_role[role_name] = valid
        print(f"\n  {role_name} ({node_type}, {len(valid)} valid bytes):")
        # Group by suffix length
        by_len = {}
        for byte_val, suffix in valid:
            by_len.setdefault(len(suffix), []).append((byte_val, suffix))
        for L in sorted(by_len):
            entries = by_len[L]
            byte_strs = [f"0x{b:02X}('{suffix_to_str(s)}')" for b, s in entries]
            print(f"    L={L}: {', '.join(byte_strs)}")

    # --- 3. Find compact assignments (prefer short, uniform suffix lengths) ---
    print("\n" + "=" * 72)
    print("RECOMMENDED ASSIGNMENTS (shortest uniform suffix length)")
    print("=" * 72)

    inner_roles = [(r, t, d) for r, t, d in ROLES if t == "inner"]
    final_roles = [(r, t, d) for r, t, d in ROLES if t == "final"]

    # Find minimum suffix length that provides enough inner bytes
    for L in range(1, 7):
        inner_at_L = [
            (b, s) for b, s in generate_valid_bytes("inner", L)
            if len(s) == L
        ]
        final_at_L = [
            (b, s) for b, s in generate_valid_bytes("final", L)
            if len(s) == L
        ]
        if len(inner_at_L) >= len(inner_roles) and len(final_at_L) >= len(final_roles):
            print(f"\n  Minimum uniform suffix length: {L}")
            print(f"  Inner candidates at L={L}: {len(inner_at_L)} (need {len(inner_roles)})")
            print(f"  Final candidates at L={L}: {len(final_at_L)} (need {len(final_roles)})")

            # Show all possible assignments at this length
            from itertools import combinations, permutations

            inner_combos = list(combinations(inner_at_L, len(inner_roles)))
            final_combos = list(combinations(final_at_L, len(final_roles)))

            print(f"\n  Possible inner assignments: {len(inner_combos)}")
            print(f"  Possible final assignments: {len(final_combos)}")

            # Show first few complete assignments
            assignment_count = 0
            print(f"\n  All valid assignments at L={L}:")
            for ic in inner_combos:
                for fc in final_combos:
                    all_bytes = [b for b, s in ic] + [b for b, s in fc]
                    if len(set(all_bytes)) == len(all_bytes):  # pairwise distinct
                        assignment_count += 1
                        if assignment_count <= 20:
                            print(f"\n  --- Assignment {assignment_count} ---")
                            for i, (role_name, _, desc) in enumerate(inner_roles):
                                b, s = ic[i]
                                print(f"    {role_name:20s}: 0x{b:02X}  "
                                      f"suffix='{suffix_to_str(s)}'  ({desc})")
                            for i, (role_name, _, desc) in enumerate(final_roles):
                                b, s = fc[i]
                                print(f"    {role_name:20s}: 0x{b:02X}  "
                                      f"suffix='{suffix_to_str(s)}'  ({desc})")

            if assignment_count > 20:
                print(f"\n  ... and {assignment_count - 20} more assignments")
            print(f"\n  Total valid assignments at L={L}: {assignment_count}")
            break

    # --- 4. Verify roundtrip ---
    print("\n" + "=" * 72)
    print("ENCODING ROUNDTRIP VERIFICATION")
    print("=" * 72)
    test_cases = [
        ([1, 1], 0x07, "K12 message-hop final"),
        ([1, 1, 0], 0x0B, "K12 message-hop inner"),
        ([0, 1], 0x06, "K12 chaining-hop final"),
        ([1, 1, 1, 1], 0x1F, "SHAKE"),
    ]
    all_pass = True
    for suffix, expected_byte, label in test_cases:
        actual_byte = suffix_to_byte(suffix)
        recovered = byte_to_suffix(actual_byte)
        ok = actual_byte == expected_byte and recovered == suffix
        status = "✓" if ok else "✗"
        print(f"  {status} {label}: suffix '{suffix_to_str(suffix)}' → "
              f"0x{actual_byte:02X} (expected 0x{expected_byte:02X}), "
              f"roundtrip: '{suffix_to_str(recovered)}'")
        if not ok:
            all_pass = False
    if all_pass:
        print("  All roundtrip checks passed.")
    else:
        print("  *** ROUNDTRIP FAILURES ***")
        sys.exit(1)


if __name__ == "__main__":
    main()
