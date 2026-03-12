# TW128: Tree-Parallel Authenticated Encryption

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.10</td></tr>
  <tr><th>Date</th><td>2026-03-05</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

TW128 is an authenticated-encryption scheme with associated data (AEAD) built on a duplex-based Sakura flat-tree
topology, using Keccak-p[1600,12] as the underlying permutation, targeting 128-bit security. The construction enables
SIMD acceleration (NEON, AVX-512) on large inputs: the final node encrypts the first chunk directly, then absorbs chain
values from parallel leaves that process subsequent chunks, producing a single MAC tag. The master key, nonce, and
associated data are absorbed into a shared base duplex state via `encode_string` encoding; each tree node clones this
base state with a distinct index.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 2. Parameters

| Symbol   | Value             | Description                                         |
|----------|-------------------|-----------------------------------------------------|
| f        | Keccak-p[1600,12] | per RFC 9861, 1600-bit state, 12 rounds             |
| C        | 32                | Capacity (bytes); key and chain value size          |
| R        | 168               | Sponge rate (bytes); $`1600/8 - 32 = 168`$          |
| $`\tau`$ | 32                | Tag size (bytes); equal to C for this instantiation |
| $`K_L`$  | 32                | Key length (bytes)                                  |
| B        | 8192              | Chunk size (bytes), matching KangarooTwelve         |

**Constraint verification.** $`C + 8 = 40 \leq 167 = R - 1`$. $`\max(\tau, C) = 32 < 168 = R`$.

## 3. Dependencies

TW128 depends on the Keccak-p[1600,12] permutation and the NIST SP 800-185 encoding functions
(`encode_string`, `left_encode`).

**`Keccak-p[1600,12]`:** The 12-round Keccak permutation on a 1600-bit state, as defined in RFC 9861. This is the
underlying permutation for the TW128 duplex.

**`encode_string(x)`:** As defined in NIST SP 800-185: `left_encode(len(x) * 8) || x`. Used to encode the master key,
nonce, and associated data into the base duplex state with injective, self-delimiting framing.

## 4. Duplex

The duplex operates on a standard Keccak sponge with the same permutation and rate/capacity parameters as
TurboSHAKE128. The `domain_byte` parameter to `_duplex_pad_permute` is supplied by the caller; Section 5 defines
the four domain separation bytes used by TW128.

TW128 is a duplex-based authenticated encryption construction (BDPVA11 §4) using overwrite-mode absorption
(BDPVA11 §6.2, Algorithm 5; Theorem 2). Encryption and authentication share a single duplex state, with the tag
squeezed from the same state that produced the ciphertext. This is a dedicated (non-composed) AE construction,
distinct from the generic composition paradigms (encrypt-and-MAC, MAC-then-encrypt, encrypt-then-MAC) analyzed by
Bellare and Namprempre (BN00).

The `encrypt` and `decrypt` operations write ciphertext directly into the rate, yielding identical state evolution
under both directions (Section 6.2). Intermediate (non-final) encrypt/decrypt blocks fill the
full R = 168 byte rate and permute without padding; only terminal operations (initialization, chain value finalization, and the tag
`_duplex_pad_permute` in the AEAD construction) apply multi-rate padding via `pad_permute`. For full-rate
blocks, a write-only state update is also faster than read-XOR-write on most architectures.

> **Rate distinction.** Initialization absorbs at effective rate R-1 = 167 bytes: padding (domain byte at `pos`,
> `0x80` at position R-1) requires one byte reserved for the domain/padding frame, so `pad_permute` triggers when `pos`
> reaches R-1. Intermediate encrypt/decrypt blocks use the full R = 168 byte rate with no padding overhead, permuting
> via raw `keccak_p1600` when `pos` reaches R. Terminal operations (chain value finalization and the tag `_duplex_pad_permute`) call
> `pad_permute` at whatever `pos` the final partial block leaves, accommodating both full and partial final blocks.

The duplex is defined by the following reference implementation. `keccak_p1600` is defined in
Appendix B.

<!-- begin:code:ref/duplex.py:duplex_all -->
```python
from collections import namedtuple

R = 168   # Sponge rate (bytes).
C = 32    # Capacity (bytes); key and chain value size.
TAU = 32  # Tag size (bytes).
B = 8192  # Chunk size (bytes).

# S: 200-byte Keccak state (bytearray). pos: current offset into the rate.
_DuplexState = namedtuple("_DuplexState", ["S", "pos"])

def _duplex_pad_permute(D: _DuplexState, domain_byte: int) -> _DuplexState:
    """Apply TurboSHAKE padding and permute. Resets pos to 0."""
    S = bytearray(D.S)
    S[D.pos] ^= domain_byte
    S[R - 1] ^= 0x80
    keccak_p1600(S)
    return _DuplexState(S, 0)

def _duplex_encrypt(D: _DuplexState, plaintext: bytes) -> tuple[_DuplexState, bytes]:
    """Encrypt plaintext, overwriting the rate with ciphertext."""
    S, pos = bytearray(D.S), D.pos
    ct = bytearray()
    for p in plaintext:
        ct.append(p ^ S[pos])
        S[pos] = ct[-1]
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos), bytes(ct)

def _duplex_decrypt(D: _DuplexState, ciphertext: bytes) -> tuple[_DuplexState, bytes]:
    """Decrypt ciphertext, overwriting the rate with ciphertext."""
    S, pos = bytearray(D.S), D.pos
    pt = bytearray()
    for c in ciphertext:
        pt.append(c ^ S[pos])
        S[pos] = c
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos), bytes(pt)

def _duplex_absorb(D: _DuplexState, data: bytes) -> _DuplexState:
    """XOR-absorb data into the rate."""
    S, pos = bytearray(D.S), D.pos
    for b in data:
        S[pos] ^= b
        pos += 1
        if pos == R:
            keccak_p1600(S)
            pos = 0
    return _DuplexState(S, pos)
```
<!-- end:code:ref/duplex.py:duplex_all -->

> [!NOTE]
> `_duplex_pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at $`R-1`$). Initialization
> uses domain byte `0x08`; chain value finalization uses `0x0B`; the tag `_duplex_pad_permute` in
> `_tree_process` uses `0x07` (n=1) or `0x06` (n>1). Intermediate encrypt/decrypt blocks use the full
> $`R = 168`$ byte rate and permute without padding (`keccak_p1600` directly), matching standard unpadded sponge absorb
> for non-final blocks. Both `_duplex_encrypt` and `_duplex_decrypt` overwrite the rate with ciphertext, so state
> evolution is identical regardless of direction. `_duplex_absorb` XOR-absorbs data into the rate without padding,
> permuting via raw `keccak_p1600` when the rate is full. Chain value finalization calls `_duplex_pad_permute` to mix
> all data before squeezing; the output fits in a single squeeze block since $`C = 32 \ll R = 168`$.

## 5. Construction

### Notation

- `||`: Byte string concatenation.
- `LEU64(i)`: The 8-byte little-endian encoding of integer `i`.

The encodings used here (`left_encode`, `encode_string`, `length_encode`) are defined as Python functions in Appendix B.
`left_encode` and `encode_string` follow NIST SP 800-185; `length_encode` follows RFC 9861.

### Tree Topology

TW128 uses the Sakura final-node-growing topology with kangaroo hopping, following KangarooTwelve (ePrint
2016/770, Sections 1 and 3.3). The final node (index 0) is a duplex that encrypts chunk 0 directly (the "message
hop"). Chunks 1 through $`n-1`$ are processed by independent leaf duplexes that produce chain values (the "chaining hop").

For $`n = 1`$, the final node encrypts the entire message and produces the tag via `pad_permute(0x07)`. The Sakura frame
bits are: message hop `'1'` + final `'1'` = `'11'`, yielding domain byte `0x07` (delimited suffix `'111'`).

For $`n > 1`$, the final node is a duplex that:

1. Clones the base state, absorbs `LEU64(0)`, and calls `pad_permute(0x08)`.
2. Encrypts chunk 0 (the message hop).
3. Absorbs `HOP_FRAME` (`0x03 || 0x00^7`), the Sakura message-hop / chaining-hop framing.
4. Absorbs chain values $`\mathit{cv}_1 \;\|\; \cdots \;\|\; \mathit{cv}_{n-1}`$.
5. Absorbs `length_encode(n-1) || 0xFF || 0xFF`.
6. Calls `pad_permute(0x06)` and squeezes the $`\tau`$-byte tag.

The transition from overwrite-mode encryption (step 2) to XOR-mode absorption (step 3) does not require a permutation:
overwrite-mode encryption writes `ct[j] = pt[j] XOR S[pos]` into `S[pos]`, which produces the same state byte as
XOR-absorbing the plaintext (`S[pos] ^= pt[j]`), since both yield `S[pos] = ct[j]`. The duplex state after encrypting
chunk 0 is therefore identical to the state that would result from XOR-absorbing the same plaintext, and both modes
resume from the same `pos` offset. Section 6.2 provides the full algebraic argument.

The Sakura frame bits at the tag are: chaining hop `'0'` + final `'1'` = `'01'`, yielding domain byte `0x06`
(delimited suffix `'011'`). The fields above are:

- **`HOP_FRAME`** (8 bytes): the Sakura message-hop / chaining-hop frame `'110^{62}'` packed LSB-first as `0x03 || 0x00^7`.
- **`cv_i`** (C = 32 bytes each): the chain value squeezed from leaf $`i`$ (for $`i = 1, \ldots, n-1`$).
- **`length_encode(n-1)`**: the Sakura coded nrCVs field encoding the number of chain values ($`n-1`$, since the final
  node handles chunk 0), encoded per RFC 9861.
- **`0xFF || 0xFF`**: the Sakura interleaving block size encoding $`I = \infty`$ (no block interleaving); mantissa and
  exponent both `0xFF`.

Each domain byte stores a variable-length suffix bit-string LSB-first, with a delimiter `1` bit immediately after the
last suffix bit. The last suffix bit encodes the Sakura node type: `1` for final nodes, `0` for inner/leaf nodes.
Inner-node bytes use 3-bit suffixes (delimiter at bit 3); final-node bytes use 2-bit suffixes (delimiter at bit 2).
Final-node separability follows directly from the last suffix bit.

The `0xFF || 0xFF` suffix is defined as `SAKURA_SUFFIX` in the reference code (Section 5.1).

The following table lists the four domain separation bytes with their Sakura suffix encodings:

| Byte   | Usage                           | Sakura suffix | Node type |
|--------|---------------------------------|---------------|-----------|
| `0x07` | Tag, n=1 (single final)         | `11`          | final     |
| `0x06` | Tag, n>1 (chaining final)       | `01`          | final     |
| `0x0B` | Leaf chain value                | `110`         | inner     |
| `0x08` | Init (key/index absorption)     | `000`         | inner     |

**Domain separation.** The master key, nonce, and AD are absorbed into a shared base duplex state via
`encode_string(K) || encode_string(N) || encode_string(AD)`. Each tree node clones this base state,
absorbs a distinct `LEU64(index)`, and calls `pad_permute(0x08)`: the final node uses index 0,
while leaves use indices $`1, \ldots, n-1`$. The final node's tag domain byte (`0x06` or `0x07`) is distinct from all
leaf domain bytes (`0x08`, `0x0B`), providing an additional layer of separation.

**Encoding injectivity.** The chaining-hop suffix `length_encode(n-1) || 0xFF || 0xFF` is self-delimiting: `0xFF`
cannot be a valid `length_encode` byte-count (chain-value counts fit in at most 8 bytes), so the interleaving block
size bytes are unambiguously terminal, and the byte immediately preceding them gives the byte-count of $`n-1`$. Given
$`n-1`$, the chain values are parsed as $`n-1`$ consecutive $`C`$-byte blocks following the `HOP_FRAME`.

### 5.1 Tree Processing

The `_tree_process` function is the core of TW128. It takes the master key, nonce, associated data, plaintext (or
ciphertext), and a direction flag, and returns the processed data and a MAC tag.

**`_tree_process(key, nonce, ad, data, direction) -> (output, tag)`**

*Inputs:*

- `key`: A C-byte master key. MUST be uniformly random.
- `nonce`: A byte string of at least 16 bytes. MUST be unique per `(key, ad)` pair.
- `ad`: Associated data of any length (may be empty).
- `data`: Plaintext (direction = "E") or ciphertext (direction = "D") of any length (may be empty). Maximum length is
  $`(2^{64} - 1) \cdot B`$ bytes, since leaf indices are encoded as 8-byte little-endian integers.
- `direction`: `"E"` for encryption, `"D"` for decryption.

*Outputs:*

- `output`: Ciphertext or plaintext. Same length as `data`.
- `tag`: A $`\tau`$-byte MAC tag.

*Procedure.* The context prefix `encode_string(K) || encode_string(N) || encode_string(AD)` is absorbed into a
fresh duplex state to form the **base state**. Each tree node clones this base state, absorbs `LEU64(index)`,
and calls `pad_permute(0x08)` to produce the node's keyed init state. This design absorbs the key, nonce,
and AD exactly once, then reuses the result across all nodes via cloning.

<!-- begin:code:ref/tw128.py:internal_functions -->
```python
# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def _tree_process(key: bytes, nonce: bytes, ad: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for TW128 encrypt/decrypt."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    op = _duplex_encrypt if direction == "E" else _duplex_decrypt

    # Build base state: absorb encode_string(K) || encode_string(N) || encode_string(AD).
    prefix = encode_string(key) + encode_string(nonce) + encode_string(ad)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Final node: clone base, absorb LEU64(0), pad_permute 0x08.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, ct0 = op(F, chunks[0])
    out_parts = [ct0]

    if n == 1:
        # Single node: message hop '11' -> 0x07
        F = _duplex_pad_permute(F, 0x07)
        return out_parts[0], bytes(F.S[:TAU])

    # Multi-node: message hop framing '110^{62}'
    F = _duplex_absorb(F, HOP_FRAME)

    # Leaves 1..n-1: independent, parallel.
    cvs = []
    for i, chunk in enumerate(chunks[1:], start=1):
        # Clone base, absorb LEU64(i), pad_permute 0x08.
        L = _DuplexState(bytearray(base.S), base.pos)
        L = _duplex_absorb(L, i.to_bytes(8, "little"))
        L = _duplex_pad_permute(L, 0x08)
        L, ct_i = op(L, chunk)
        out_parts.append(ct_i)
        L = _duplex_pad_permute(L, 0x0B)
        cvs.append(bytes(L.S[:C]))

    # Absorb chain values into final node.
    for cv in cvs:
        F = _duplex_absorb(F, cv)

    # Chaining hop suffix.
    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)

    # Chaining hop '01' -> 0x06
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])
```
<!-- end:code:ref/tw128.py:internal_functions -->

The final node (index 0) always encrypts chunk 0. Leaf operations for chunks 1 through $`n-1`$ are independent and may
execute in parallel. Tag computation begins as soon as all chain values are available. Decryption produces the
same tag as encryption because both `encrypt` and `decrypt` write ciphertext into the duplex rate (Section 4).

> [!CAUTION]
> For production implementations, avoid repeated byte-string concatenation (`final_input += ...`) when building the
> final node input; prefer preallocation or list/join style buffer construction.

### 5.2 Encrypt / Decrypt

**`TW128.Encrypt(K, N, AD, M) -> ct || tag`**\
**`TW128.Decrypt(K, N, AD, ct || tag) -> M | None`**

**Master-key requirement.** `K` MUST be a uniformly random key of exactly 32 bytes (256 bits).

**Context encoding injectivity.** The `encode_string` encoding (NIST SP 800-185) makes the concatenation
`encode_string(K) || encode_string(N) || encode_string(AD)` injective:
each field is prefixed with its `left_encode`d bit-length (`left_encode(8*len(x))`), so no `(K, N, AD)` triple can
produce the same absorption stream as a different triple. This guarantees that distinct contexts produce distinct
base states (and therefore distinct per-node init inputs).

<!-- begin:code:ref/tw128.py:aead_functions -->
```python
import hmac

def tw128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    assert len(K) == C, "K must be exactly 32 bytes"
    ct, tag = _tree_process(K, N, AD, M, "E")
    return ct + tag

def tw128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    assert len(K) == C, "K must be exactly 32 bytes"
    if len(ct_tag) < TAU:
        return None
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = _tree_process(K, N, AD, ct, "D")
    return pt if hmac.compare_digest(tag, tag_expected) else None
```
<!-- end:code:ref/tw128.py:aead_functions -->

## 6. Security Properties

This section gives a complete reduction from TW128 AEAD security to the ideal-permutation assumption on
Keccak-p[1600,12]. The argument proceeds in three stages:

1. **Context-prefix injectivity (Section 6.4).** `encode_string` injectivity ensures distinct `(K, N, AD)` triples
   produce distinct absorption streams. Each node clones the base state and appends a distinct `LEU64(index)`, so every
   node's init π-input is distinct across both contexts and indices. By the outer-keyed sponge result (ADMV15),
   init outputs are pseudorandom.
2. **Per-node PRF (Section 6.2).** MRV15 FKD covers each node's duplex operations.
3. **AEAD goals (Sections 6.6–6.9).** Under pseudorandom init states, each AEAD goal (IND-CPA, INT-CTXT, IND-CCA2)
   reduces to keyed-duplex PRF properties of the leaf ciphers: pseudorandomness of rate outputs,
   structural state equivalence, and fixed-key bijection.

All bounds are in the ideal-permutation model for Keccak-p[1600,12], with capacity $`c = 256`$ bits and $`\tau = 32`$
tag bytes. Nonce-misuse resistance is explicitly out of scope: all IND-CPA and IND-CCA2 claims assume a nonce-respecting
adversary. Related-key security is also out of scope: all claims assume the master key $`K`$ is uniformly random and
independent of any other keys in the system.

> [!CAUTION]
> **Nonce reuse is catastrophic.** Reusing the same $`(K, N, AD)`$ triple with different equal-length
> messages produces identical keystreams, leaking the XOR of all plaintexts (two-time pad). This
> enables full plaintext recovery given one known plaintext. Nonce uniqueness per $`(K, AD)`$ pair is a
> hard security requirement (Section 7.3), not a quality-of-implementation concern.

**Length leakage.** TW128 ciphertexts reveal the exact plaintext length: `|ct| = |M|` (plus the
fixed $`\tau`$-byte tag). This is inherent to any stream-cipher-based AEAD and is not mitigated by this
construction. Applications requiring length hiding must pad plaintexts before encryption.

**Assumption scope.** Concrete bounds in this section are conditional on Keccak-p[1600,12] behaving as an ideal
permutation at the claimed workloads. This is a modeling assumption, not a proof about reduced-round Keccak-p itself.

> [!IMPORTANT]
> Public cryptanalysis on Keccak-family primitives includes reduced-round results with explicit round counts.
> On standard Keccak-224/256 instances: practical 4-round collisions and 5-round near-collisions (Hamming
> distance 5–10) are reported in DDS14. On reduced-capacity contest instances (Keccak[c=160]): 6-round
> collision solutions are publicly reported (Keccak Crunchy Crypto Contest). In the raw-permutation setting
> (Keccak-f[1600] with full state access, no keying): differential distinguishers reach 8 rounds at
> complexity $`2^{491.47}`$ (DGPW11), and zero-sum distinguishers reach 16 rounds (of the original 18) at
> complexity $`2^{1023.88}`$ (AM09). All known results above 6 rounds are in the unkeyed raw-permutation
> setting and require state access or control that the keyed sponge/duplex denies.
> (See the Keccak Team third-party table and reduced-round references in Section 9.)
>
> These results do not directly invalidate the TW128 security analysis because TW128 uses a
> keyed sponge/duplex setting with 256-bit capacity, strict domain separation, and workload limits;
> nevertheless, future cryptanalysis could change the practical margin, so deployments should treat the
> concrete bounds as conditional.

### 6.1 Model and Notation

Concrete numerical evaluations in this section use TW128 parameters.

Let:

- $`\sigma`$: total online Keccak-p calls performed by the construction across all oracle queries
  (including base-state prefix absorption, leaf-duplex, and chaining-hop tag permutation calls).
- $`t`$: adversary offline Keccak-p calls — direct evaluations of $`\pi`$ and $`\pi^{-1}`$ in the
  ideal-permutation model. This is an analysis parameter, not a deployment-controlled quantity; Section 7.3
  provides guidance on choosing $`t`$ for bound evaluation.
- $`S`$: total number of decryption/verification forgery attempts in one security experiment (per key epoch).
- $`q_{\mathrm{ctx}}`$: number of distinct contexts (one per distinct $`(K, N, AD)`$ triple; the context encoding
  is defined in Section 6.4).
- $`n = \max(1, \lceil |M|/B \rceil)`$: number of chunks for a message of length $`|M|`$.
- Throughout Section 6, $`c = 8C = 256`$ denotes the capacity in bits.

Define:

```math
\varepsilon_{\mathrm{cap}} \;\stackrel{\mathrm{def}}{=}\; \frac{(\sigma + t)^2}{2^{c+1}}.
```
This is the capacity birthday bound. Let $`\mathsf{Bad}_{\mathrm{perm}}`$ be the event that the ideal permutation
exhibits a capacity-part collision among any pair of the $`\sigma + t`$ total evaluations (online construction calls and
adversary offline calls). A *capacity-part collision* occurs when two distinct Keccak-p evaluations produce equal
256-bit capacity outputs (the low $`c`$ bits of the 1600-bit state). By the birthday bound,
$`\Pr[\mathsf{Bad}_{\mathrm{perm}}] \leq \binom{\sigma+t}{2} \cdot 2^{-c} \leq \varepsilon_{\mathrm{cap}}`$.

Let $`\varepsilon_{\mathrm{ks}}(q, \ell, \mu, N)`$ denote the MRV15 PRF advantage bound for $`q`$ keyed-sponge or
keyed-duplex evaluations of at most $`\ell`$ input blocks (or duplexing calls) each, $`\mu`$ total blocks across all
evaluations ($`\mu \leq q\ell`$), and $`N`$ adversary offline $`\pi`$-queries. MRV15 Theorems 1 (FKS) and 2 (FKD) yield
bounds of the same three-term structure but with different capacity terms; see Section 6.2.

**PRP/PRF switching.** The ideal permutation samples without replacement. Throughout Section 6, "uniform" and
"independent" outputs from $`\pi`$ on distinct inputs are understood modulo the PRP/PRF switching distance
$`\sigma^2 / 2^{1601}`$, which is negligible compared to $`\varepsilon_{\mathrm{cap}}`$ for $`c = 256 \ll 1600`$. This cost
is not repeated in individual theorem statements.

Throughout this section, "capacity state," "capacity output," and "capacity projection" all refer to the 256-bit
low-order portion of the 1600-bit Keccak-p state.

**Exact uniformity under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$.** In the ideal-permutation model, conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$, every $`\pi`$-call on a fresh (never-before-seen) 1600-bit input produces a truly
uniform 1600-bit output — not merely computationally pseudorandom. Freshness has two components:

1. **Among construction calls.** $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ ensures pairwise distinct capacity outputs, and the
   Domain Separation Lemma (Section 6.3) ensures distinct rate contents across roles. Together these guarantee no two
   construction $`\pi`$-calls share a full 1600-bit input.
2. **With respect to adversary offline queries.** An adversary $`\pi/\pi^{-1}`$ query may coincide with a construction
   call's input. The match probability per query depends on which secret component prevents collision:

   | Call type | Secret component | Match probability |
   |---|---|---|
   | Init ($`\mathcal{I}`$) | Key in rate | $`\le 1/2^k`$ |
   | Intermediate | Capacity from prior $`\pi`$-output | $`\le 1/2^c`$ |

   The total freshness-failure probability is at most $`\mu\, t / 2^{\min(k,c)}`$, where
   $`\mu`$ is the total duplexing calls across all base-state absorption, leaf, and final-node evaluations. This cost is charged
   as part of the online-vs-offline term in the decomposition (Section 6.5). The base-state absorption π-calls
   (absorbing the `encode_string` prefix) are accounted for in σ and the $`\mu\, t / 2^k`$ term.

Conditioned on both $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ and adversary-query freshness, all construction $`\pi`$-outputs
are exactly uniform. This principle is the engine for the bare-bound analyses in Sections 6.7–6.9: once both conditions
are accounted for, the remaining advantage reduces to structural collision and forgery probabilities over truly uniform
values.

Unless stated otherwise, these symbols are scoped to one fixed master key (one key epoch / one experiment instance).
Section 6.10 (CMT-4) is an exception: the adversary controls the keys in that game.

### 6.2 Keyed-Duplex PRF Framework (MRV15)

TW128 leaf ciphers are keyed duplexes: after initialization, each leaf
interleaves absorb and squeeze operations (absorb plaintext block → permute →
squeeze keystream/tag). This matches MRV15's Full Keyed Duplex (FKD) model
rather than the single-evaluation Full Keyed Sponge (FKS). The two theorems
yield bounds of different form in the capacity term.

**Theorem (MRV15, Theorem 2 — FKD).** Let $`\mathrm{FKD}^{\pi}_K`$ be the
full-state keyed duplex instantiated with an ideal permutation $`\pi`$ on $`b`$
bits, capacity $`c`$, and key length $`k`$. For an adversary making $`q`$ duplex
evaluations, each consisting of at most $`\ell`$ duplexing calls, $`\mu \leq q\ell`$
total duplexing calls across all evaluations, and $`N`$ offline $`\pi`$-queries:

```math
\mathrm{Adv}^{\mathrm{ind}}_{\mathrm{FKD}^{\pi}_K,\,\pi}(q, \ell, \mu, N)
  \;\leq\;
  \frac{(q\ell)^2}{2^b}
  \;+\; \frac{(q\ell)^2}{2^c}
  \;+\; \frac{\mu N}{2^k}.
```
**Theorem (MRV15, Theorem 1 — FKS).** Let $`\mathrm{FKS}^{\pi}_K`$ be the
full-state keyed sponge with the same parameters. For an adversary making $`q`$
sponge evaluations of at most $`\ell`$ input blocks each, $`\mu \leq q\ell`$ total
blocks, and $`N`$ offline $`\pi`$-queries:

```math
\mathrm{Adv}^{\mathrm{ind}}_{\mathrm{FKS}^{\pi}_K,\,\pi}(q, \ell, \mu, N)
  \;\leq\;
  \frac{2(q\ell)^2}{2^b}
  \;+\; \frac{2q^2\ell}{2^c}
  \;+\; \frac{\mu N}{2^k}.
```
Both theorems are due to Mennink, Reyhanitabar, and Vizár (Asiacrypt 2015).
The structural difference is in the capacity term: FKD has $`(q\ell)^2 / 2^c`$
(scaling with $`q^2\ell^2`$), while FKS has $`2q^2\ell / 2^c`$ (scaling with
$`q^2\ell`$). FKS thus provides a tighter capacity bound per query when $`\ell`$ is
large.

The parameters are $`b = 1600`$, $`c = 256`$, $`k = c = 256`$. Each
leaf is a single duplex evaluation ($`q = 1`$), so at the per-leaf level the FKD
bound simplifies to $`\ell^2/2^b + \ell^2/2^c + \mu N/2^k`$, and
$`\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)`$ captures the advantage for leaf $`i`$
with $`l_i`$ duplexing calls.

**Term analysis.** The FKD bound has three terms:

1. **Full-state birthday** $`\frac{(q\ell)^2}{2^{1600}}`$: negligible at
   $`b = 1600`$. Even for $`q\ell = 2^{128}`$ this term is below $`2^{-1344}`$.

2. **Online-vs-online capacity term** $`\frac{(q\ell)^2}{2^{256}}`$: scales with
   $`q^2\ell^2`$. For *leaves* with $`q = 1`$, this simplifies to
   $`\ell^2/2^{256}`$. With $`\ell \approx 49`$ blocks per full 8192-byte chunk
   ($`\lfloor 8192/168 \rfloor + 1`$), the per-leaf capacity term is
   $`49^2 / 2^{256} \approx 2^{-244.8}`$, which is negligible.

3. **Online-vs-offline term** $`\frac{\mu N}{2^{256}}`$: dominant when the
   adversary's offline computation budget $`N`$ (denoted $`t`$ elsewhere in this
   document) is significant. This term is linear in the total absorbed block
   count $`\mu`$ rather than quadratic. It is identical in FKS and FKD.

**Key-loading: outer-keyed sponge.** MRV15's FKD initialises with the key placed
in the capacity portion of the state: $`S \gets 0^{b-k} \| K`$. TW128
instead absorbs the key into the rate via standard sponge absorption: the
byte-string $`K \| \mathrm{LEU64}(\mathit{index})`$ is XOR'd into rate positions,
followed by pad-and-permute with domain byte $`\mathtt{0x08}`$. This is the
*outer-keyed sponge* construction $`\mathrm{Sponge}(K \| M)`$, whose PRF security
is established by Andreeva, Daemen, Mennink, and Van Assche (ADMV15, FSE 2015).
The single-target bound (Theorems 5 + 6, combined in the ideal-permutation
model) is:

```math
\mathrm{Adv}^{\mathrm{ind}[1]}_{\mathrm{OKS}}(\sigma,\mu,t)
  \;\leq\; \frac{\sigma^2 + 2\mu\, t}{2^c} + \lambda(t) + \frac{2\!\left(\frac{k}{r}\right)\!t}{2^b},
```
where $`\sigma`$, $`\mu`$, and $`t`$ are as defined in Section 6.1 (translating
ADMV15's online-query count $`M \to \sigma`$ and offline-query count $`N \to t`$), and $`\lambda(t)`$
is a key-recovery term bounded in ADMV15 Lemma 2. The dominant
terms $`\sigma^2/2^c`$ and $`2\mu\, t/2^c`$ match MRV15's capacity and online-vs-offline
terms up to a constant factor. The remaining terms ($`\lambda(t)`$ and
$`2(k/r)\,t/2^b`$) are negligible at $`b = 1600`$.

After the init permutation, the full state is
$`\pi(K \| \mathit{index} \| \mathtt{0x08}\text{-pad} \| 0^c)`$. Since $`K`$ is
secret and uniform, this input is unique with overwhelming probability, and the
resulting state is uniformly random over the adversary's view. This is exactly
the precondition for MRV15's internal proof: the subsequent duplex operation
proceeds from a uniform state. The init call is accounted for in $`\mu`$.

**Overwrite-mode coverage.** MRV15 structurally assumes XOR-absorb. TW128's
encrypt operation produces identical state evolution:
$`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ followed by
$`S[\mathit{pos}] \gets \mathit{ct}[j]`$ yields the same state byte as
$`S[\mathit{pos}] \mathrel{\oplus}= \mathit{pt}[j]`$, since
$`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ in both paths.
Overwrite mode is therefore algebraically identical to XOR-absorb for state
evolution. Each ciphertext byte $`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ is derived from a
rate byte of the prior $`\pi`$-output. In the FKD model, the observable output at each duplexing call is the
post-permutation state; the ciphertext bytes are a deterministic, invertible function (XOR with chosen plaintext)
of these outputs. No information beyond the FKD-modeled outputs is revealed. BDPVA11 (Algorithm 5,
Theorem 2) provides independent confirmation of overwrite-mode security.

**Squeeze-phase coverage.** MRV15's FKD includes explicit squeeze output at each
duplexing call. TW128's tags ($`\tau = 32`$ bytes) and chain values
($`C = 32`$ bytes) are single-block squeezes well within one rate block
($`R = 168`$ bytes). These outputs are directly covered by Theorem 2.

### 6.3 Domain Separation Lemma

**Lemma (Domain separation).** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ (Section 6.1), the construction's $`\pi`$-calls partition into disjoint sets by role, such that no two calls from different roles share a full 1600-bit input.

| Set | Role | Domain byte | Distinguishing mechanism |
|-----|------|-------------|--------------------------|
| $`\mathcal{I}`$ | Duplex init | `0x08` | Padded, domain byte `0x08` |
| $`\mathcal{C}`$ | Chain value | `0x0B` | Padded, domain byte `0x0B` |
| $`\mathcal{T}_s`$ | Single-node tag | `0x07` | Padded, domain byte `0x07` |
| $`\mathcal{T}_f`$ | Chaining-hop tag | `0x06` | Padded, domain byte `0x06` |
| $`\mathcal{U}`$ | Unpadded intermediate | — | Secret capacity from keyed init |

*Proof sketch.*

**Capacity-chain separation.** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, all $`\pi`$-output capacities are pairwise distinct. Two $`\pi`$-calls whose input capacities are both inherited from prior $`\pi`$-outputs therefore have distinct input capacities. When one call inherits its capacity and the other starts from zero capacity (fresh state), the inherited capacity equals zero with probability at most $`\sigma / 2^c`$ (a single-target preimage, dominated by $`\varepsilon_{\mathrm{cap}}`$).

Three cases:

1. **Padded vs. padded (different domain bytes).** Each `pad_permute` call XORs its domain byte at the current offset `pos` in the rate. Two sub-cases:

   - **(a) Same `pos`.** Both calls apply `pad_permute` at the same byte offset. The different domain bytes are XOR'd at the same rate position, so the rate content differs at that byte regardless of capacity.

   - **(b) Different `pos`.** By capacity-chain separation, the calls have distinct input capacities unless both start from zero capacity. Chain value ($`\mathcal{C}`$), single-node tag ($`\mathcal{T}_s`$), and chaining-hop tag ($`\mathcal{T}_f`$) calls all inherit their capacity from prior $`\pi`$-outputs, so they never start from zero capacity. Only init ($`\mathcal{I}`$) calls start from zero capacity (the base-state prefix absorption begins from a fresh state). Since all init calls use domain byte `0x08` and reach `pad_permute` at the same `pos` (after absorbing the prefix plus `LEU64(index)`), they fall under case (a) if their domain bytes match — distinct indices ensure distinct rate content at the same `pos`. The total collision probability is dominated by $`\varepsilon_{\mathrm{cap}}`$.

2. **Padded vs. unpadded.** Every unpadded intermediate $`\pi`$-call (set $`\mathcal{U}`$) inherits its capacity from a prior $`\pi`$-output. Non-init padded calls (chain value finalization, tag squeeze) also inherit their capacity from prior $`\pi`$-outputs. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, these prior outputs have pairwise distinct capacities, so any unpadded call and any non-init padded call inherit from different outputs and have distinct input capacities. Init calls start from zero capacity and are distinct from any inherited capacity except with probability dominated by $`\varepsilon_{\mathrm{cap}}`$. In both sub-cases, the capacities differ, so the full 1600-bit $`\pi`$-inputs are distinct.

3. **Within a set.** Calls within the same role are distinguished by one of two mechanisms:

   - **Different contexts or indices.** Different duplex instances have different absorption streams (distinct `encode_string` prefixes or distinct `LEU64(i)` vs. `LEU64(j)`), producing distinct rate content at init and therefore distinct capacity outputs that propagate through each instance's chain.
   - **Same instance, different position.** Each call inherits the previous call's capacity output, which is pairwise distinct under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$.

   Both mechanisms apply to unpadded intermediate blocks ($`\mathcal{U}`$): cross-instance separation comes from distinct init inputs; within-instance separation comes from the capacity chain.

**Sakura suffix structure.** The domain bytes are not arbitrary constants. Each encodes a Keccak delimited suffix (ePrint 2013/231) using the standard encoding: a variable-length suffix bit-string is stored LSB-first in the byte, with a delimiter `1` bit immediately after the last suffix bit. The inner-node bytes (`0x08`, `0x0B`) use 3-bit suffixes (delimiter at bit 3), while the final-node bytes (`0x07`, `0x06`) use 2-bit suffixes (delimiter at bit 2). All follow the Keccak delimited-suffix convention. The last suffix bit encodes the Sakura node type: `0` for inner/leaf, `1` for final.

| Domain byte | Binary | Suffix (LSB-first) | Last bit | Node type |
|-------------|--------|-------------------|----------|-----------|
| `0x08` | 0000 1**000** | `000` | 0 | inner (duplex init) |
| `0x0B` | 0000 1**011** | `110` | 0 | inner (chain value) |
| `0x07` | 0000 0**111** | `11` | 1 | final (tag, n=1) |
| `0x06` | 0000 0**110** | `01` | 1 | final (tag, n>1) |

Inner/final node separability follows directly from Sakura Lemma 4: the final-node bytes (`0x07`, `0x06`) have last suffix bit `1`, while all inner/leaf bytes (`0x08`, `0x0B`) have last suffix bit `0`. Three of the four domain bytes (`0x0B`, `0x07`, `0x06`) are reused directly from KangarooTwelve's Sakura encoding, providing established cross-protocol semantics.

**Design constraint.** Future modifications to domain byte assignments MUST preserve Sakura delimited-suffix encoding compliance and the node-type partition between inner and final roles.

**Consequence.** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, each role's $`\pi`$-calls are functionally independent of every other role's. This is the precondition for Section 6.4 (context independence), Sections 6.6–6.9 (independent leaf and tag analysis), and Section 6.10 (CMT-4 commitment analysis).

### 6.4 Context Independence

This section shows that distinct `(K, N, AD, index)` tuples produce independent pseudorandom node init states,
using `encode_string` injectivity, the outer-keyed sponge result (ADMV15), and domain separation (Section 6.3).

**Context encoding.** Each $`(K, N, AD)`$ triple defines a *context*. The context encoding is:

```math
X = \mathrm{encode\_string}(K)\,\|\,\mathrm{encode\_string}(N)\,\|\,\mathrm{encode\_string}(AD).
```
Distinct triples produce distinct $`X`$ values (by injectivity of `encode_string`), so $`q_{\mathrm{ctx}}`$
(Section 6.1) equals the number of distinct triples queried.

**Base-state construction.** The context prefix $`X`$ is absorbed into a fresh duplex state via standard XOR-absorb.
Each tree node clones this base state, absorbs `LEU64(index)`, and calls `pad_permute(0x08)`. The full π-input
for the init call of node $`(K, N, AD, i)`$ is therefore determined by the absorption of
$`X \| \mathrm{LEU64}(i)`$ into a fresh state, followed by `0x08`-padding.

**Argument.**

1. **`encode_string` injectivity.** Distinct `(K, N, AD)` triples produce distinct $`X`$ values.
   Appending distinct `LEU64(i)` values within the same context, or using distinct contexts,
   produces distinct absorption streams $`X \| \mathrm{LEU64}(i)`$. Therefore every
   `(K, N, AD, i)` tuple yields a distinct pre-padding rate content.

2. **Outer-keyed sponge (ADMV15).** The master key $`K`$ is secret and uniform, and appears in the rate
   via `encode_string(K)`. By the outer-keyed sponge result (ADMV15, Theorems 5+6; see Section 6.2),
   the init π-output is pseudorandom. The single-target advantage is bounded by the ADMV15 terms,
   which are within a constant factor of $`\varepsilon_{\mathrm{cap}}`$ plus $`\mu\, t / 2^k`$.

3. **Domain separation (Section 6.3).** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, init π-calls (set
   $`\mathcal{I}`$, domain byte `0x08`) are on inputs disjoint from all other roles' π-calls. The
   init states are therefore functionally independent of all other construction components.

**Bound:**

```math
\varepsilon_{\mathrm{ctx\text{-}ind}} \le \varepsilon_{\mathrm{cap}} + \frac{\mu\, t}{2^k},
```
where $`\varepsilon_{\mathrm{cap}}`$ covers $`\mathsf{Bad}_{\mathrm{perm}}`$ (needed for domain separation and
capacity-chain distinctness), and $`\mu\, t / 2^k`$ is the online-vs-offline term from the ADMV15 outer-keyed
sponge bound. No context-collision term is needed: `encode_string` injectivity is exact (not probabilistic),
and node-index distinctness is structural.

**Summary.** The fixed-key AEAD goals below (Sections 6.7–6.9) are analyzed conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$, with each node's init state treated as pseudorandom and independent.
Section 6.5 defines the bare-game framework and the total-advantage decomposition used by those sections.
CMT-4 (Section 6.10) is a multi-key notion with a standalone proof that does not use this argument.

### 6.5 Bare-Game Framework

All analyses in Sections 6.6–6.9 work conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$. The cost of this event
($`\varepsilon_{\mathrm{cap}}`$) is charged once via context independence (Section 6.4)
and does not recur. (CMT-4, Section 6.10, is a multi-key notion with a standalone bound.)

Define the **bare advantage** $`\mathrm{Adv}_{\Pi}^{\mathrm{bare}}`$ as the adversary's advantage against the
construction under independent pseudorandom per-node init states, conditioned on $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ and
adversary-query freshness (Section 6.1). Each AEAD property's total advantage decomposes as:

```math
\mathrm{Adv}_{\Pi} \le \varepsilon_{\mathrm{cap}} + \frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}.
```
where $`\mu`$ is the total absorbed blocks across all keyed construction
evaluations (base-state prefix absorption plus leaf and final-node duplexing calls). The $`\mu\, t / 2^k`$ term combines
the online-vs-offline cost from the outer-keyed sponge (Section 6.4) and per-node freshness (Section 6.1).
Under the exact uniformity principle, all bare-bound analyses reduce to structural collision
and forgery probabilities over truly uniform values.

### 6.6 Leaf Security Lemmas

Assume a pseudorandom init state for each node, as established by context independence (Section 6.4).

**Lemma 1 (Keyed-duplex pseudorandomness).**
For any keyed duplex whose init state is pseudorandom (Section 6.4) and whose init π-input includes a distinct
`LEU64(i)` index, in the ideal-permutation model, the PRF advantage distinguishing the rate outputs (keystream bytes and
terminal squeeze bytes) from uniformly random is at most $`\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)`$, where $`l_i`$ is the
number of duplexing calls for leaf $`i`$ and $`t`$ is the adversary offline Keccak-p budget (Section 6.1). This holds for both overwrite-mode
absorption (used during encryption) and standard XOR-mode absorption (used during framing and chain-value absorption in the final node).

*Proof.* Each leaf has a pseudorandom init state (from context independence, Section 6.4). By the Domain Separation
Lemma (Section 6.3), under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, the leaf's $`\pi`$-calls are disjoint from all other
roles. Applying MRV15 Theorem 2 (FKD, Section 6.2) — including the outer-keyed initialization (ADMV15) and
overwrite-mode coverage established there — the PRF advantage for leaf $`i`$ is at most
$`\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)`$, where $`l_i`$ is the number of duplexing calls for leaf $`i`$.

**Lemma 2 (State-direction equivalence).**
For a fixed init state (determined by context and index $`i`$) and any plaintext-ciphertext pair of equal length, `encrypt` and `decrypt` induce identical
internal states because both write ciphertext bytes into the rate. This is structural (no probabilistic component): the overwrite rule `S[pos] = ct[j]` is executed
identically in both directions. In `encrypt`, the ciphertext byte is computed as `pt[j] XOR S[pos]` and then written
back via the overwrite; in `decrypt`, the ciphertext byte is already available and written directly. Either way, the
state after the overwrite contains the same ciphertext byte at the same position. The `pos` counter also evolves
identically: both directions increment `pos` by 1 per byte and permute when `pos` reaches $`R`$, so permutation
boundaries are the same. Subsequent permutation inputs -- and therefore the tag -- are identical.

**Lemma 3 (Fixed-key bijection).**
For a fixed init state and message length, the encrypt function is a deterministic, invertible map on the message
space. Each ciphertext byte $`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ uniquely determines
$`\mathit{pt}[j]`$ given the state, and the state evolution (overwriting $`S[\mathit{pos}]`$ with $`\mathit{ct}[j]`$) is
identical in both directions (Lemma 2). Therefore encryption is a bijection between equal-length plaintexts and
ciphertexts. Invertibility is witnessed by the decrypt function, which reverses each byte-level XOR step given
the same state evolution (Lemma 2). Because each chunk is processed by an independent leaf with its own init state (determined by context and index $`i`$),
and each leaf's encrypt is individually a bijection, the full $`n`$-leaf encrypt function (which concatenates the
per-leaf outputs) is also a bijection between equal-length plaintexts and ciphertexts for a fixed key and chunking.
Chunking is determined solely by total message length (ceiling division by $`B`$), so equal-length messages always have
identical chunking.

This bijection is used in Section 6.10 (CMT-4) to rule out two different plaintexts opening the same ciphertext under
one key.

**Final-node tag (n = 1).** For single-chunk messages, the final node is a single duplex that clones the base state,
absorbs `LEU64(0)`, and calls `pad_permute(0x08)`, then encrypts the entire message (overwrite mode, covered by Lemma 2), and squeezes
the tag via `pad_permute(0x07)`. This is one continuous FKD evaluation.

**Final-node tag (n > 1).** For multi-chunk messages, the final node is a single duplex that:

1. Clones the base state, absorbs `LEU64(0)`, and calls `pad_permute(0x08)`.
2. Encrypts chunk 0 (overwrite mode, covered by Lemma 2).
3. XOR-absorbs HOP_FRAME and chain values.
4. Applies `pad_permute(0x06)` and squeezes the tag.

This is also one continuous FKD evaluation. The overwrite-mode equivalence (Lemma 2) covers the encryption phase;
standard XOR-absorb covers framing and chain-value absorption.

**Tag pseudorandomness (both cases).** MRV15 Theorem 2 (FKD) applies to the entire final-node sequence, with
outer-keyed initialization covered by ADMV15 (Section 6.2). By domain separation (Section 6.3, sets
$`\mathcal{T}_s`$ and $`\mathcal{T}_f`$), the tag-squeeze $`\pi`$-call is disjoint from all other construction calls.
The tag is therefore pseudorandom with advantage at most $`\varepsilon_{\mathrm{ks}}(1, \ell_f, \ell_f, t)`$, where
$`\ell_f`$ is the total duplexing calls in the final node.

**Consequence.**
By Lemma 3 (fixed-key bijection), distinct plaintexts produce distinct ciphertexts under a fixed key, so the tag can be
viewed equivalently as a function of plaintext or ciphertext.

### 6.7 IND-CPA (Nonce-Respecting)

```
Game IND-CPA_b(A):
  K <-$ {0,1}^{|K|}
  b' <- A^{Enc_b}
  return b'

Oracle Enc_b(N, AD, M0, M1):
  require |M0| = |M1|
  return TW128.Encrypt(K, N, AD, M_b)
```

By context independence (Section 6.4), it suffices to bound
$`\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}}`$ -- the IND-CPA advantage of the construction under
independent pseudorandom per-node init states.

**Claim.** Conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$:
$`\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} = 0`$.

*Justification.* Conditioned on $`\neg\mathsf{Bad}_{\mathrm{perm}}`$:

- Each encryption query uses a fresh nonce (nonce-respecting), so each context is distinct (Section 6.4).
- Distinct contexts produce independent pseudorandom init states (Section 6.4).
- Under a pseudorandom init state and the ideal permutation conditioned on
  $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, the ciphertext distribution is independent of the adversary's plaintext choice.
  The argument proceeds by induction over rate blocks. The overwrite rule ensures plaintext-independence propagates
  across blocks: because ciphertext bytes (not plaintext bytes) are written into the state, the duplex state after
  each block depends only on the ciphertext and the inherited capacity.

  - *Block 0:* The `init` step clones the base state, absorbs `LEU64(index)`, and applies $`\pi`$ via `pad_permute`.
    The secret context prefix ensures no other call shares this rate content, and domain separation ensures no
    cross-role collision, so the $`\pi`$-input is novel and the resulting state is truly uniform by the exact
    uniformity principle of Section 6.1. Each ciphertext byte
    $`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ is uniform because XOR with a uniform value is uniform.
    The overwrite rule writes $`\mathit{ct}[j]`$ into the state, so the post-block state depends only on uniform
    ciphertext values and is plaintext-independent.

  - *Block $`j > 0`$:* $`\pi`$ is applied at the block boundary. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, the
    capacity output of this $`\pi`$-call is distinct from all other $`\pi`$-output capacities. Block $`j`$'s first
    $`\pi`$-call inherits this capacity as its input capacity. Every other $`\pi`$-call's input capacity is either
    zero (init calls) or inherited from a different $`\pi`$-output (which is pairwise distinct under
    $`\neg\mathsf{Bad}_{\mathrm{perm}}`$), so no other call shares this input capacity, and the full 1600-bit
    $`\pi`$-input is novel regardless of the rate content. The $`\pi`$-output is therefore uniformly random, and
    the same XOR and overwrite arguments as block 0 apply. If the block is a final partial block ($`0 \le k < R`$
    bytes followed by `pad_permute`), the $`k`$ ciphertext bytes are uniform by the same argument, and the
    `pad_permute` $`\pi`$-call is on a fresh input (distinct capacity), so the squeeze output is also uniform.

  - *Multi-chunk ($`n > 1`$):* Distinct leaf indices (same base state, different `LEU64(i)`) produce distinct init
    $`\pi`$-inputs. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, the resulting capacity chains remain disjoint, so
    each leaf's $`\pi`$-calls are independent of every other leaf's. Applying the single-duplex induction to each
    leaf, every leaf's ciphertext chunk is independently uniform. The chain values squeezed from leaves
    $`1, \ldots, n{-}1`$ are uniform $`\pi`$-outputs from fresh inputs. The final node absorbs these chain values
    and produces the tag; its tag-squeeze $`\pi`$-call is on a fresh input (distinct capacity), so the tag is also
    uniform. The joint distribution of all chunks' ciphertexts and the tag is therefore independent of the
    adversary's plaintext choice.

The bare IND-CPA advantage is therefore zero. The total bound follows from the decomposition in Section 6.5.

### 6.8 INT-CTXT

```
Game INT-CTXT(A):
  K <-$ {0,1}^{|K|}; S <- {}
  win <- A^{Enc, Forge}
  return win

Oracle Enc(N, AD, M):
  C <- TW128.Encrypt(K, N, AD, M)
  S <- S union {(N, AD, C)}
  return C

Oracle Forge(N, AD, C):
  if (N, AD, C) in S: return bot
  return TW128.Decrypt(K, N, AD, C) != None
```

**Claim.** $`\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}.`$

*Justification.* Conditioned on $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, each
forgery attempt targets a context with a pseudorandom init state (Section 6.4). By the exact uniformity principle (Section 6.1), the tag-squeeze $`\pi`$-call has a fresh input
(distinct capacity state under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$), so the tag is a truly uniform $`\tau`$-byte value. Each forgery attempt — i.e., a (ciphertext, tag) pair not previously output by the
encryption oracle (standard INT-CTXT definition) — must guess the correct $`\tau`$-byte tag value, succeeding with
probability at most $`2^{-8\tau}`$.

Even if the adversary has previously queried encryption on the same context and observed one valid tag, a different
ciphertext produces a different tag. The core mechanism (**byte-level divergence**): let $`p`$ be the first byte
position where a forged ciphertext differs from the legitimate one within a duplex. Both computations process identical
bytes up to $`p`$, so their states agree. At $`p`$, the overwrite rule writes different ciphertext bytes, changing the
rate. The next $`\pi`$-input differs in at least one rate byte while sharing the same capacity (same chain up to $`p`$),
so the full 1600-bit input is distinct from the legitimate computation's. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$,
this input is also distinct from all other construction calls' inputs, so $`\pi`$ produces a uniform output. Each
subsequent $`\pi`$-call inherits its capacity from this fresh output, so freshness cascades through to the tag squeeze.

For same-length forgeries, at least one ciphertext byte differs. Applying byte-level divergence:

- *$`n = 1`$:* The forged ciphertext diverges within the single duplex. The tag is uniform and independent of the
  legitimate tag.
- *$`n > 1`$, chunk 0:* Chunk 0 is processed by the final-node duplex directly. The first differing byte triggers
  byte-level divergence within the final node's state chain, which cascades through all subsequent $`\pi`$-calls —
  including HOP_FRAME absorption, chain-value absorption, and the tag squeeze. The tag is therefore uniform and
  independent of the legitimate tag.
- *$`n > 1`$, leaf chunk $`i \geq 1`$:* The leaf's state diverges at the first differing byte, and freshness cascades
  through to the chain-value squeeze. The forged chain value is therefore independent of the legitimate one. The final
  node XOR-absorbs this different chain value, altering the rate of a subsequent $`\pi`$-call. The capacity at that
  point is unchanged (same final-node chain up to the absorption), but the rate differs, so the $`\pi`$-input is fresh
  and the tag is uniform.

For different-length forgeries, the mechanism depends on where the length difference falls:

- *Same $`n > 1`$, chunk 0 length differs:* The final node's `pos` after encrypting chunk 0 differs, shifting all
  subsequent absorption boundaries (HOP_FRAME, chain values, chaining-hop suffix) and altering a $`\pi`$-input's
  rate content.
- *Same $`n`$, last leaf length differs:* The leaf's chain-value squeeze occurs at a different duplex position,
  producing an independent chain value; absorption of this chain value alters the final node's rate, making the
  tag-squeeze $`\pi`$-input fresh.
- *Different $`n`$:* The number of absorbed chain values and the `length_encode(n-1)` suffix both change,
  structurally altering the final node's absorption stream.
- *$`n = 1`$ / $`n > 1`$ boundary:* The tag domain byte itself differs (`0x07` vs `0x06`).

In all sub-cases, the tag-squeeze $`\pi`$-input is distinct from any legitimate computation's, so the tag is uniform.

If the forgery targets a different context
$`(N', AD')`$, the init state differs (Section 6.4), producing a different init $`\pi`$-input and hence an independent state chain
(no capacity collision under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$). Across $`S`$ attempts (union bound):

```math
\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le \frac{S}{2^{8\tau}}.
```
The total bound follows from the decomposition in Section 6.5.

If tags are truncated to $`T<\tau`$ bytes, replace $`S/2^{8\tau}`$ with $`S/2^{8T}`$. Truncation below $`\tau/2 = 16`$ bytes reduces the INT-CTXT bound below the 128-bit security target at the Section 7.3 baseline forgery budget.

### 6.9 IND-CCA2 (Nonce-Respecting)

IND-CCA2 follows from IND-CPA and INT-CTXT via the generic composition theorem of Bellare and Namprempre (BN00).

**Step 1: Bare-level composition.** By BN00 Theorem 3.2, for the internal functions under a fixed
random key:

```math
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} + 2\,\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}}.
```
An IND-CCA2 adversary has access to both an encryption oracle and a decryption oracle. By INT-CTXT, the decryption
oracle rejects all adversary-crafted queries (except with probability
$`\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}}`$), so it provides no useful information beyond what the
encryption oracle already reveals. Removing the decryption oracle reduces the game to IND-CPA. BN00's proof bounds
$`\Pr[\mathrm{IND\text{-}CCA2} \Rightarrow 1]`$ in terms of $`\Pr[\mathrm{IND\text{-}CPA} \Rightarrow 1]`$ and
$`\Pr[\mathrm{forge}]`$ without any factor of 2. The factor appears when converting to advantages because IND-CCA2
and IND-CPA advantages are both defined as $`2\Pr[\mathsf{game} \Rightarrow 1] - 1`$, so the factor of 2 cancels
between them, but INT-CTXT advantage is defined as the raw probability $`\Pr[\mathrm{forge}]`$, so the factor of 2
survives on that term.

**Step 2: Substitute bare bounds.** From Sections 6.7 and 6.8:
$`\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} = 0`$ and
$`\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}`$. Therefore:

```math
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \frac{2S}{2^{8\tau}}.
```
**Step 3: Total bound.** The total bound follows from the decomposition in Section 6.5.

> *Note on construction type.* As noted in Section 4, TW128 is a dedicated (non-composed) AE construction that does
> not fit any of BN00's three generic composition paradigms. The BN00 composition theorem (Theorem 3.2) does not
> require any particular internal structure — it states that *any* symmetric encryption scheme satisfying both IND-CPA
> and INT-CTXT also satisfies IND-CCA2. Sections 6.7 and 6.8 establish IND-CPA and INT-CTXT for TW128 directly, so
> the theorem applies. The ciphertext dependence of the tag (overwrite mode writes ciphertext bytes into the rate
> before the tag squeeze) is what makes INT-CTXT hold despite the shared duplex state.

Nonce reuse for the same $`(K,N,AD)`$ is out of scope for this claim and breaks standard nonce-respecting
IND-CCA2 formulations.

### 6.10 CMT-4

This theorem follows the Bellare–Hoang CMT-4 committing-security notion [BH22, §3]: a ciphertext should not admit
two distinct valid openings under any choice of keys. Unlike the fixed-key properties in Sections 6.7–6.9, this is a
multi-key notion — the adversary controls all inputs including the master keys — and the proof does not flow through
context independence (Section 6.4).

```
Game CMT-4(A):
  (C*, (K, N, AD, M), (K', N', AD', M')) <- A^{pi, pi^{-1}}
  require (K, N, AD, M) != (K', N', AD', M')
  require |M| = |M'|
  return TW128.Encrypt(K, N, AD, M) = C*
     and TW128.Encrypt(K', N', AD', M') = C*
```

The adversary has direct access to the ideal permutation $`\pi`$ and its inverse (no encryption oracle is needed since the
scheme is deterministic and the adversary knows the keys). Define $`L`$ and $`L'`$ as the base states after absorbing the
`encode_string` prefix for each context.

- **Case 1: same context, different message.** $`(K,N,AD)=(K',N',AD')`$, so $`M \neq M'`$ (since
  full tuples are distinct). Both openings use the same base state and the same chunking
  (equal-length messages). By Lemma 3 (fixed-key bijection, Section 6.6), the encrypt function is a
  bijection on equal-length messages for a fixed init state. Two different messages cannot produce the same
  ciphertext. This case is **impossible**.
- **Case 2: different context, base-state collision.** $`(K,N,AD)\neq(K',N',AD')`$ but $`L = L'`$. The
  $`\mathrm{encode\_string}`$ encoding is injective and self-delimiting, so distinct $`(K,N,AD)`$ triples produce
  distinct absorption streams. A collision $`L = L'`$ on distinct inputs is a state collision in the sponge.
  In the ideal-permutation model, sponge collision resistance gives
  $`\Pr[\text{Case 2}] \leq (t + \sigma_v)^2 / 2^{c+1}`$,
  where $`t`$ is the adversary's offline $`\pi`$-query budget and $`\sigma_v`$ is the $`\pi`$-calls for the two
  verification encryptions in the game.
- **Case 3: different context, different base states.** $`L \neq L'`$. Both encryptions must produce the
  same $`C^\star = \mathit{ct}^\star \| T^\star`$. Fix the first opening $`(L, M)`$ and its full evaluation
  under $`\pi`$, which determines $`C^\star`$ and in particular the tag $`T^\star`$. For each candidate
  $`L' \neq L`$, the second opening's init $`\pi`$-input differs in the rate ($`L \neq L'`$ at the same
  rate positions). Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, no capacity collision merges the subsequent
  duplex chains, so every $`\pi`$-call in the second opening is on an input distinct from the first
  opening's $`\pi`$-calls. In particular, the tag-squeeze $`\pi`$-input of the second opening is fresh:
  over the random choice of $`\pi`$, the probability that it maps to a state whose first $`\tau`$ bytes
  equal $`T^\star`$ is $`1/2^{8\tau}`$. Since each candidate requires at least one unique $`\pi`$-query
  (the init call for $`L'`$), the adversary can evaluate at most $`t + \sigma_v`$ candidates within their
  query budget. By a union bound, the probability over $`\pi`$ that any candidate yields $`T' = T^\star`$
  is at most $`(t + \sigma_v)/2^{8\tau}`$. Tag matching is a necessary condition for $`C^\star`$ agreement,
  so the additional requirement that the ciphertext portions match can only reduce this probability.
  The $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ conditioning cost is subsumed by the $`(t + \sigma_v)^2 / 2^{c+1}`$ term.

Therefore:

```math
\mathrm{Adv}_{\mathrm{CMT\text{-}4}}(\mathcal{A}) \le \frac{(t + \sigma_v)^2}{2^{c+1}} + \frac{t + \sigma_v}{2^{8\tau}}.
```
For $`c = 256`$, $`\tau = 32`$: both terms are $`\leq 2^{-128}`$ when $`t + \sigma_v \leq 2^{64}`$. The first term gives $`(2^{64})^2/2^{257} \approx 2^{-129}`$; the second gives $`2^{64}/2^{256} = 2^{-192}`$.

Tag truncation degrades the second term to $`(t + \sigma_v)/2^{8T}`$; for $`T < 16`$ and $`t = 2^{64}`$, this exceeds $`2^{-128}`$.

### 6.11 Summary of Bounds

Each property's total advantage combines the context-independence cost (Section 6.4) with the bare advantage
(Sections 6.7–6.9):

```math
\mathrm{Adv}_{\Pi} \le \varepsilon_{\mathrm{cap}} + \frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}.
```
| Property | $`\mathrm{Adv}^{\mathrm{bare}}`$ | Total |
|----------|-------------------------------|-------|
| IND-CPA  | $`0`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k`$ |
| INT-CTXT | $`S / 2^{8\tau}`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k + S / 2^{8\tau}`$ |
| IND-CCA2 | $`2S / 2^{8\tau}`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k + 2S / 2^{8\tau}`$ |

CMT-4 (Section 6.10) has a standalone multi-key bound that does not use the bridge decomposition:

```math
\mathrm{Adv}_{\mathrm{CMT\text{-}4}}(\mathcal{A}) \le \frac{(t + \sigma_v)^2}{2^{c+1}} + \frac{t + \sigma_v}{2^{8\tau}}.
```
Where:

- $`\varepsilon_{\mathrm{cap}} = (\sigma + t)^2 / 2^{c+1}`$ is the capacity birthday bound.
- $`\mu\, t / 2^k`$ is the online-vs-offline term covering base-state prefix absorption and per-node duplexing calls (Sections 6.1 and 6.4).

MRV15 capacity terms are within a constant factor of $`\varepsilon_{\mathrm{cap}}`$: the per-leaf FKD capacity terms sum to $`\sum \ell_i^2 / 2^c \leq (\sum \ell_i)^2 / 2^c`$; since each $`\ell_i`$ counts duplexing calls that are a subset of the total online $`\pi`$-calls $`\sigma`$, we have $`\sum \ell_i \leq \sigma \leq \sigma + t`$, giving $`(\sum \ell_i)^2 / 2^c \leq 2\varepsilon_{\mathrm{cap}}`$.
Parameters are defined in Section 6.1.

## 7. Operational Security

### 7.1 Chunk Reordering, Length Changes, and Empty Input

- Reordering chunks changes leaf-index binding (base-state clone + `LEU64(index)`), so recomputed tag changes.
- Truncation/extension changes chunk count $`n`$, changing `length_encode(n-1)` in the chaining-hop suffix.
- Empty plaintext uses $`n=1`$: the final node encrypts the empty message and produces the tag via `pad_permute(0x07)`.

### 7.2 Side Channels

Implementations MUST be constant-time with respect to secret-dependent control flow and memory access.

- No lookup tables indexed by secret state bytes.
- Tag verification MUST use constant-time equality.
- Partial-block logic may branch on public length, not on secret data.

### 7.3 Operational Usage Limits (Normative)

To claim the 128-bit security target in this specification, deployments MUST enforce per-master-key usage limits (a key
epoch) and rotate to a fresh master key before exceeding them.

Implementations MUST maintain the following per-key-epoch counters:

- $`q_{\mathrm{enc}}`$: number of encryption invocations.
- $`\sigma_{\mathrm{total}} = \sigma_{\mathrm{tw128}} + \sigma_{\mathrm{other\ keccak\ uses\ in\ scope}}`$ (i.e., all Keccak-p evaluations sharing the same ideal-permutation instance within one key epoch).
- $`q_{\mathrm{nonce}}`$: number of random nonces used (only for random-nonce deployments).
- $`S`$: number of failed decryption/verification attempts processed (forgery attempts).

Required baseline profile (MUST):

- Enforce $`\sigma_{\mathrm{total}} \le 2^{60}`$.
- Define and enforce an encryption-invocation cap $`q_{\mathrm{enc}} \le q_{\mathrm{enc,cap}}`$ per key epoch.
- Enforce nonce uniqueness per key epoch. Deterministic nonces (counters or sequences) MUST NOT repeat within one key
  epoch; random-nonce deployments SHOULD use a large nonce space (e.g., 192 or 256 bits).
- Nonces MUST be at least 16 bytes. Random nonces SHOULD be at least 192 bits.
- Tag output MUST be at least 16 bytes ($`T \geq \tau/2`$). Truncation below 16 bytes voids the 128-bit security target for both INT-CTXT and CMT-4.
- For deterministic nonces, choose $`q_{\mathrm{enc,cap}}`$ so nonce values cannot wrap or repeat within the epoch.
- If random nonces are used, additionally enforce
  $`q_{\mathrm{nonce}}(q_{\mathrm{nonce}}-1)/2^{b_n+1} \le p_{\mathrm{nonce}}`$ for nonce bit-length $`b_n`$ and chosen nonce-collision target
  $`p_{\mathrm{nonce}}`$.
- Define and enforce a failed-verification budget $`S_{\mathrm{cap}}`$ per key epoch (RECOMMENDED: $`S_{\mathrm{cap}} = 2^{32}`$).
  If $`S > S_{\mathrm{cap}}`$, implementations MUST stop accepting further decryption attempts for that epoch and rotate to
  a fresh key epoch before resuming.
- On any cap exceedance (workload, invocation, nonce, or failed-verification policy), implementations MUST rotate to a
  fresh key epoch before any further encryption.

Analysis interpretation (normative for this profile): evaluate the Section 6 bounds using default offline-work profile
$`t = 2^{64}`$.

Expert profile (non-normative): deployments with stronger review/monitoring may choose workload caps above $`2^{60}`$, up
to $`2^{64}`$, using the same counter model.

Security interpretation remains the Section 6 bound family evaluated at observed counters, with adversary offline budget
parameter $`t`$ treated as an analysis parameter (not an operationally measurable quantity).

**Multi-user security.** For deployments spanning $`U`$ independent master keys, the
$`\mathsf{Bad}_{\mathrm{perm}}`$ event is global (a capacity collision among *any* pair of the system-wide
$`\sigma + t`$ evaluations), so $`\varepsilon_{\mathrm{cap}}`$ is charged once with $`\sigma = \sum_u \sigma_u`$.
The remaining per-key terms (online-vs-offline key recovery and bare advantages)
are independent across keys and summed via union bound. The total multi-user advantage is:

```math
\mathrm{Adv}_{\mathrm{multi}} \le \varepsilon_{\mathrm{cap}}(\sigma_{\mathrm{global}}, t) + U \cdot \left(\frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}\right).
```
Non-normative sensitivity profiles for reviewers:

| Profile  | Offline-work parameter | Typical audience                      |
|----------|------------------------|---------------------------------------|
| Baseline | $`t = 2^{64}`$           | default deployment conformance        |
| Audit    | $`t = 2^{60}`$           | realistic adversary budget; confirms margin at lower workloads |
| Extended | $`t = 2^{72}`$           | research-oriented stress analysis     |

Profile choice changes only analytical interpretation of bounds; it does not change algorithm behavior, implementation
requirements, or interoperability.

Appendix C remains non-normative operational guidance for instrumentation and budgeting workflows.

### 7.4 Implementation Design Callouts (Non-Normative)

TW128's tree topology exists to exploit data-level parallelism: independent leaf chunks can be encrypted or
decrypted simultaneously using SIMD permutation kernels. A scalar implementation that processes leaves one at a time
will be bottlenecked by permutation latency; a vectorized implementation that processes 4–8 leaves per kernel
invocation can achieve roughly 20× higher throughput on contemporary hardware. The guidance below describes the
techniques that make this possible, progressing from data layout through scheduling.

**High-level principles:**

- **Saturate the widest available permutation kernel.** Throughput scales with the number of parallel Keccak states
  processed per instruction. Prefer the widest kernel the platform supports, falling back to narrower kernels for
  remainders.
- **Keep chunk 0 on the fast path.** Chunk 0 is encrypted directly through the final node's duplex (the kangaroo
  message hop). Single-chunk messages never enter the tree machinery.
- **Share one scheduling pipeline for encrypt and decrypt.** Both directions use the same chunk batching, index
  binding, and chain-value accumulation logic; only the XOR direction differs.
- **Keep domain bytes and index mapping exact.** The constants `0x08`, `0x0B`, `0x07`, `0x06` and the
  base-state cloning pattern (clone the shared prefix state, absorb `LEU64(index)`, `pad_permute(0x08)` — index 0 for the final node, 1 through $`n-1`$ for leaves) are structural for
  interoperability and security analysis.
- **No misuse resistance (MRAE).** TW128 is not SIV-style: nonce reuse leaks plaintext XOR (Section 6.7).
  Applications requiring nonce-misuse resistance should use a dedicated MRAE construction.

**PlSnP lane-major state layout.** The key data structure for parallel Keccak is an N-way interleaved state, following
the pattern the Keccak team calls "Parallel Lanes, Serial N Permutations" (PlSnP). Rather than storing N independent
200-byte Keccak states, a PlSnP layout groups the same lane across all N instances into a single contiguous vector:

```
State4 layout (N = 4, 25 lanes × 32 bytes):

  lane 0:  [ a₀  a₁  a₂  a₃ ]   ← 4 × uint64, one per instance
  lane 1:  [ b₀  b₁  b₂  b₃ ]
    ⋮
  lane 24: [ y₀  y₁  y₂  y₃ ]
```

Each row is one SIMD register wide (e.g. 64 bytes for 8×64-bit on AVX-512). This layout has
two critical properties:

1. **Absorb is a single vector XOR per lane.** To absorb a rate block across all N instances, load the corresponding
   plaintext bytes from N input streams into a vector and `VPXOR` it into the lane — one instruction for N states.
2. **Permutation rounds operate on all N states simultaneously.** Every θ/ρ/π/χ/ι step is the same vector operation
   applied to 25 registers, processing N permutations for the cost of one.

The N input streams are typically laid out at a fixed stride (the chunk size, 8192 bytes), so absorbing lane `i` across
all instances is a gather from `input + instance × stride + i × 8`. On AVX-512, `VPGATHERQQ` performs well at width 8;
on platforms without hardware gather, loading each instance's lane individually and packing into a vector with insert
or shuffle instructions is used instead.

**Batch scheduling.** Given a batch of complete chunks, process them in groups of the platform's lane width, padding
the final group if needed. For example, on x86-64 (8-wide), 11 chunks would be scheduled as one full x8 batch, one
padded x8 batch processing 3 chunks (with 5 unused lanes), yielding the same result as processing 8 + 3. Each batch
initializes an N-way PlSnP state by absorbing `key ‖ LEU64(leaf_index)` into each instance, runs the fused
absorb-permute loop over the chunk data, then extracts N chain values. Chain values are absorbed into the final node
incrementally — there is no need to buffer them all before finalizing.

The kernel width is platform-dependent:

| Platform | Kernel width | Implementation |
|----------|-------------|----------------|
| amd64 + AVX-512 | x8 (ZMM, state-resident in Z0–Z24) | Native |
| amd64 + AVX2 | x8 (YMM, lane-major, 2 × x4 rounds) | Native |
| arm64 + NEON | x4 (ASIMD, 2 × x2 rounds) | Native |
| Scalar fallback | x1 | Serial |

**Fused absorb-permute loops.** The inner loop of each leaf processes a full rate block (168 bytes = 21 lanes) per
iteration. A fused implementation absorbs the block and immediately permutes without storing and reloading the PlSnP
state between iterations. This eliminates 25×N loads and 25×N stores per block that a non-fused design would require to
move the PlSnP state between separate absorb and permute functions. At x8 width on AVX-512, where the state occupies
all 25 ZMM registers, the savings are substantial.

**Preserve empty and single-chunk fast paths.** Empty inputs and single-chunk messages (≤ 8192 bytes) never enter the
tree — they are processed entirely through the final node's duplex. Keep these paths free of tree-scheduling overhead,
as they dominate latency-sensitive workloads.

## 8. Comparison with Traditional AEAD

TW128 differs from traditional AEAD in several respects.

**Integrated context absorption.** The master key, nonce, and AD are absorbed directly into the duplex base state
via `encode_string` encoding. There is no separate KDF or nonce-processing layer; the context is part of the
duplex initialization.

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs -- they prove authenticity but are not
necessarily pseudorandom. TW128's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (Section 6.6). This stronger property is useful for protocols that derive further keying material from the tag.

### 8.1 Operational Safety Limits

Operational planning assumptions used in this section: $`p = 2^{-50}`$, 1500-byte messages, TW128 cost
$`\approx 10`$ Keccak-p calls/message (10 duplex calls), $`\ell \approx 49`$ max input blocks per keyed-duplex
evaluation, and per-key accounting (single key / key epoch). Figures are conditional on the Section 6 model assumptions
for Keccak-p[1600,12] and the selected offline-work profile.

Under the MRV15 keyed-sponge PRF framework (Section 6.2), per-leaf FKD capacity terms (Theorem 2) are negligible since
each leaf has $`q = 1`$. For a conservative estimate, set $`q`$ to the number of TW128 encryptions and $`\ell = 49`$
(worst-case blocks absorbed per message, which overstates the per-evaluation input length and is therefore safe). With $`c = 256`$ and target
$`p = 2^{-50}`$: $`q^2 \le 2^{256-50} / (2 \cdot 49) \approx 2^{199}`$, so $`q \lesssim 2^{99.5}`$ messages. At 1500
bytes/message the proof-bound volume is approximately $`2^{80}`$ GiB per key epoch. This is an analytical upper bound,
not the practical deployment limit when random nonces are used.

For deployment planning, use:

```math
\text{practical per-key volume} = \min(\text{proof-bound volume},\ \text{nonce-collision-limited volume}).
```
With uniformly random 128-bit nonces and collision target $`p = 2^{-50}`$, the nonce budget is approximately
$`q_{\mathrm{nonce}} \lesssim 2^{39.5}`$ encryptions per key (birthday approximation), so at 1500 bytes/message:

```math
\text{nonce-collision-limited volume} \approx 2^{39.5} \cdot 1500\ \text{bytes} \approx 2^{20.1}\ \text{GiB}.
```
TW128 supports longer nonces (e.g., 192 or 256 bits) with the same construction; this increases the random-nonce
collision budget in the usual birthday way.

Example planning table (collision target $`p = 2^{-50}`$, record size = 1500 bytes):

| Nonce size | Record size | Limiting factor  | Approx safe volume per key epoch |
|------------|-------------|------------------|----------------------------------|
| 128-bit    | 1500 B      | nonce collisions | $`\approx 2^{20.1}`$ GiB           |
| 192-bit    | 1500 B      | nonce collisions | $`\approx 2^{52.1}`$ GiB           |
| 256-bit    | 1500 B      | proof bound      | $`\approx 2^{80}`$ GiB             |

For a different record size, scale the nonce-collision-limited rows linearly with bytes/record and then apply the same
minimum rule against the proof-bound volume.

Configured usage limits SHOULD be driven by nonce policy and key-epoch rotation controls (Section 7.3), not by the asymptotic
proof-bound figure alone.

## 9. References

- **[ADMV15]** Andreeva, E., Daemen, J., Mennink, B., and Van Assche, G. "Security of Keyed Sponge Constructions Using
  a Modular Proof Approach." FSE 2015. Proves PRF security of both inner-keyed and outer-keyed sponge variants. The
  outer-keyed result covers TW128's rate-absorbed key initialization (Section 6.2).
- **[AM09]** Aumasson, J.-P. and Meier, W. "Zero-sum distinguishers for reduced Keccak-f and for the core functions of
  Luffa and Hamsi." 2009. https://www.aumasson.jp/data/papers/AM09.pdf. Presents zero-sum distinguishers up to 16 rounds.
- **[BDPVA07]** Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007.
  Establishes the flat sponge claim (a heuristic generic security bound for random sponges based on inner-collision
  analysis). Referenced in the non-normative note in Section 6.2.
- **[BDPVA11]** Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass
  Authenticated Encryption and Other Applications." SAC 2011. IACR ePrint 2011/499. Establishes the duplex-sponge
  equivalence (Lemma 3: each duplex output equals a sponge evaluation on concatenated padded inputs), proves SpongeWrap
  AEAD security bounds (Theorem 1), and gives overwrite-mode security (BDPVA11 §6.2, Algorithm 5, Theorem 2: Overwrite
  is as secure as Sponge); establishes that all intermediate rate outputs -- not just terminal squeezes -- are covered by
  the duplex security bound.
- **[BDPVA13]** Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing."
  IACR ePrint 2013/231. Defines the tree hash coding framework used by KangarooTwelve and TW128.
- **[BDPVAVK16]** Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B.
  "KangarooTwelve: fast hashing based on Keccak-p." IACR ePrint 2016/770. Security and design context for the
  Sakura-based tree structure.
- **[BDPVAVK23]** Bertoni, G., Daemen, J., Hoffert, S., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B.
  "TurboSHAKE." IACR ePrint 2023/342. Primary specification and design rationale for TurboSHAKE. Referenced in
  Appendix C for system-wide Keccak budgeting; not a TW128 dependency.
- **[BH22]** Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." EUROCRYPT 2022.
  Defines the CMT-4 committing security notion (§3, E-notion with $`\ell = 4`$). Section 6.10 uses this game directly.
- **[BN00]** Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the
  Generic Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2; used in Section 6.9.
- **[CDMP05]** Coron, J.-S., Dodis, Y., Malinaud, C., and Puniya, P. "Merkle-Damgård Revisited: How to Construct a Hash
  Function." CRYPTO 2005. Applies the MRH indifferentiability composition theorem to hash function constructions;
  referenced in the non-normative note in Section 6.4.
- **[DDS14]** Dinur, I., Dunkelman, O., and Shamir, A. "New attacks on Keccak-224 and Keccak-256." FSE 2012; published
  as "Improved practical attacks on round-reduced Keccak" in Journal of Cryptology 27(4), 2014. Reports practical
  4-round collisions and 5-round near-collision results in standard Keccak-224/256 settings.
- **[DGPW11]** Duc, A., Guo, J., Peyrin, T., and Wei, L. "Unaligned Rebound Attack - Application to Keccak." IACR
  ePrint 2011/420. Gives differential distinguishers up to 8 rounds of Keccak internal permutations.
- **[MRH04]** Maurer, U., Renner, R., and Holenstein, C. "Indifferentiability, Impossibility Results on Reductions, and
  Applications to the Random Oracle Methodology." TCC 2004. Introduces indifferentiability and the core composition
  theorem framework used for random-oracle replacement arguments.
- **[MRV15]** Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex:
  Applications to Authenticated Encryption." Asiacrypt 2015. IACR ePrint 2015/541. Primary security framework for
  TW128. Proves beyond-birthday-bound PRF security for the full-state keyed sponge (Theorem 1, FKS) and full-state
  keyed duplex (Theorem 2, FKD) in the ideal-permutation model. Theorem 2 (FKD) is used for leaf ciphers.
  Used throughout Section 6.
- **[RFC 9861]** KangarooTwelve and TurboSHAKE.
- **[RSS11]** Ristenpart, T., Shacham, H., and Shrimpton, T. "Careful with Composition: Limitations of the
  Indifferentiability Framework." Eurocrypt 2011 (ePrint 2011/339 as "Careful with Composition: Limitations of
  Indifferentiability and Universal Composability"). Highlights multi-stage composition caveats; motivates explicit
  game-hop arguments in composed proofs.
- Keccak Team. "Keccak Crunchy Crypto Collision and Pre-image Contest."
  https://keccak.team/crunchy_contest.html. Public contest record for reduced-round Keccak[c=160] instances, including
  6-round collision solutions.
- Keccak Team. "Third-party cryptanalysis." https://keccak.team/third_party.html. Curated summary table of published
  cryptanalysis results and round counts across Keccak-family modes and raw permutations.

## 10. Test Vectors

All test vectors in this section are for TW128.

<!-- begin:vectors:docs/tw128-test-vectors.json:aead -->
### 10.1 TW128 Vectors

These vectors validate `tw128_encrypt` / `tw128_decrypt` (the TW128 instantiation),
including SP 800-185 `encode_string` context encoding.

#### 10.1.1 Empty Message

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | (empty) |
| M len | 0 |
| ct‖tag | `3b662f3b0a8bf7b6e12ea98994d962640912a92e2ec3352f975b5ddbe2585ea9` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.2 33-Byte Message With 5-Byte AD

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `a0 a1 a2 ... ab` |
| AD | 10 11 12 ... 14 |
| M len | 33 (`00 01 02 ... mod 256`) |
| ct‖tag | `2c7f7e2fb779fbf32ee81092375c0066941447c8422cdf2e08cf8f4468fd5c1e0fc8c3ab1ba8815222909e95724a5b51e7cc7a78032f11d674ed57e1dbf6e2224d` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.3 Multi-Chunk Message (8193 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `42 43 44 ... 61` |
| N | 12 bytes `c0 c1 c2 ... cb` |
| AD | 00 01 02 ... 10 |
| M len | 8193 (`00 01 02 ... mod 256`) |
| ct[:32] | `6ca83b65fe7b65c024d5a1401dd204ead42c857b9b677bd7ae017882c7324f8a` |
| tag | `f1e5165ef20a9f8900cbeda6d1accf0cfd0a14cbdc25e872f35ee8d6a94cd3a6` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.4 Nonce Reuse Behavior (Equal-Length Messages)

| Field | Value |
|-------|-------|
| K | 32 bytes `00 11 22 ... ff` |
| N | 12 bytes `ff ee dd cc bb aa 99 88 77 66 55 44` |
| AD | a1 a2 a3 ... a4 |
| M len | 64 (`00 01 02 ... mod 256`) |
| ct‖tag | `c19a715ad243929a38b3f51b10de301df567433d96345510dddb7efd8b236b02942868d594c5ca42cc13607013cf7317c4f0072ad46b96992b9c73549cb61051b37473c3f60887fe099f6c876694cca7f7674b0a18e7545eb8a2d2471ca6971e` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Reusing the same `(K, N, AD)` with a different message is deterministic and yields
`ct1 xor ct2 = m1 xor m2` within each rate block (168 bytes); overwrite mode causes
keystream divergence at subsequent block boundaries (validated by this vector).
Nonce reuse is out of scope for Section 6 nonce-respecting claims.

#### 10.1.5 Swapped Nonce and AD Domains

| Field | Value |
|-------|-------|
| K | 32 bytes `0f 0e 0d ... 00` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | 10 11 12 ... 1b |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `a9e740ce990470fcc4fc6d121db72f8052c8f4f664c673016b45a777985d88fb743a7976632702f82aa94c6070eca321b3581bee292825c369932ae30c8aac538c71110b52459c7170c65af30a7520d8` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Swapping `N` and `AD` (same byte length) yields a different `ct‖tag` and does not
validate the original `ct‖tag`.

#### 10.1.6 Empty AD vs One-Byte AD 00

| Field | Value |
|-------|-------|
| K | 32 bytes `88 99 aa ... ff` |
| N | 12 bytes `0c 0d 0e ... 17` |
| AD | (empty) |
| M len | 32 (`00 01 02 ... 1f`) |
| ct‖tag | `ab68bc6f9adc1dffc38719986b597af6ee7e4466db073ce610ea5cc2807bc68a951d5a14852886cb10d9b45ea1310d731286618b94cbbd3d778aae9c2f1845dd` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Empty AD and one-byte AD `00` are distinct contexts and produce different `ct‖tag`.

#### 10.1.7 Long AD (128 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 21 32 ... ff` |
| N | 12 bytes `ab ab ac ad ae af b0 b1 b2 b3 b4 b5` |
| AD | ab ab ab ... ab |
| M len | 17 (`00 01 02 ... 10`) |
| ct‖tag | `58d9cf0a4c794672fdc1c184a21794df707aa9d1a966fa1dabd2cfad617ef3ea3ce04bbade0bdc8d19dab09182dfc032dd` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.8 Rate-Minus-One Message (167 Bytes, R-1 Boundary)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 12 bytes `d0 d1 d2 ... db` |
| AD | 20 21 22 |
| M len | 167 (`00 01 02 ... mod 256`) |
| ct[:32] | `57d63a7ee7acd94a3b9ccf4bf165874eb927e4d79e139b1566a4f4492be971aa` |
| tag | `70d6a16841896e2a3ef6c61c013135444e680a268435768ff102f2a908e259c3` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.9 Exact-Rate Message (168 Bytes, R Boundary)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 12 bytes `d0 d1 d2 ... db` |
| AD | 20 21 22 |
| M len | 168 (`00 01 02 ... mod 256`) |
| ct[:32] | `57d63a7ee7acd94a3b9ccf4bf165874eb927e4d79e139b1566a4f4492be971aa` |
| tag | `c6aa75963cff9c9b904c5d371da48edf8726faeaf335aea194c211add781cf33` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.1.10 Large Nonce (32 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 32 bytes `e0 e1 e2 ... ff` |
| AD | 20 21 22 |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `3cd4a0518201c7a9312d2d2aa42e5cf968319042017e67329a6e90f80f695ab104992d1a5f9dc6ca6729034efec0d8238fac2fa4f514b4f93f5641a78f92dfe0183357a99c2875dd406208fc1b91daf3` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
<!-- end:vectors:docs/tw128-test-vectors.json:aead -->

## Appendix A. Exact Per-Query $`\sigma`$ Formula

For a single TW128 query on a message of length $`L`$ bytes with
$`n = \max(1, \lceil L / B \rceil)`$ chunks of sizes $`\ell_0, \ldots, \ell_{n-1}`$, the per-query contribution to
$`\sigma`$ is:

```math
\sigma_{\mathrm{query}} = \underbrace{\left\lfloor \frac{|\mathit{prefix}|}{R} \right\rfloor}_{\text{base-state prefix}} + \underbrace{\left(1 + \left\lfloor \frac{\ell_0}{R} \right\rfloor + d_f\right)}_{\text{final node}} + \underbrace{\sum_{i=1}^{n-1}\left(2 + \left\lfloor \frac{\ell_i}{R} \right\rfloor\right)}_{\text{leaves}}
```

where $`d_f`$ is the number of permutation calls during the final node's tag phase (1 for the tag `pad_permute`, plus
any additional calls from absorbing HOP_FRAME, chain values, and the chaining-hop suffix when $`n > 1`$).

More precisely:

- **Base-state prefix term.** $`|\mathit{prefix}|`$ is the byte length of
  `encode_string(K) || encode_string(N) || encode_string(AD)`.
  Each `encode_string` contributes `left_encode(8|x|)` (2-3 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $`|\mathit{prefix}| = (3+32) + (2+12) + (2+0) = 51`$ bytes, giving
  $`\lfloor 51 / 168 \rfloor = 0`$ Keccak-p calls (the prefix fits within a single rate block and the permutation
  occurs at the subsequent `pad_permute`, which is counted in the final-node or leaf init).
- **Final node term.** The final node (index 0) costs $`1`$ (init `pad_permute`) $`+`$
  $`\lfloor \ell_0 / R \rfloor`$ (unpadded intermediate permutations during chunk-0 encryption) $`+`$ $`d_f`$ (tag phase).
  For $`n = 1`$: $`d_f = 1`$ (one `pad_permute(0x07)`). For $`n > 1`$: $`d_f`$ accounts for absorbing the 8-byte HOP_FRAME,
  $`(n-1)`$ chain values of $`C`$ bytes each, the chaining-hop suffix ($`|\mathrm{length\_encode}(n-1)| + 2`$ bytes), and the
  final `pad_permute(0x06)`. These are XOR-absorbed contiguously into the rate starting from the position left after
  chunk-0 encryption.
- **Leaf term.** Each leaf (indices $`1, \ldots, n-1`$) costs $`2`$ (init `pad_permute` + terminal `pad_permute` for
  `chain_value`) $`+`$ $`\lfloor \ell_i / R \rfloor`$ (unpadded intermediate permutations on full-rate blocks). For a
  full $`B = 8192`$-byte chunk: $`2 + \lfloor 8192 / 168 \rfloor = 2 + 48 = 50`$. The leaf sum is empty when $`n = 1`$.

## Appendix B. Reference Implementation of Keccak-p[1600,12] and Encoding Functions

This appendix provides a reference Python implementation of the Keccak-p[1600,12] permutation and encoding
functions used by TW128. It is intended for specification clarity and test-vector generation; production
implementations should use platform-optimized Keccak libraries.

### Keccak-p[1600,12]

<!-- begin:code:ref/keccak.py:keccak_p1600 -->
```python
def keccak_p1600(state: bytearray, rounds: int = 12):
    """Apply Keccak-p[1600,rounds] to a 200-byte state in-place."""
    RC = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    # Combined rho+pi lane permutation order and rotation offsets.
    PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1]
    ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44]
    M = (1 << 64) - 1

    A = [int.from_bytes(state[8 * i : 8 * i + 8], "little") for i in range(25)]

    for ir in range(24 - rounds, 24):
        # Theta.
        C = [A[j] ^ A[j + 5] ^ A[j + 10] ^ A[j + 15] ^ A[j + 20] for j in range(5)]
        for j in range(5):
            d = C[(j - 1) % 5] ^ (((C[(j + 1) % 5] << 1) | (C[(j + 1) % 5] >> 63)) & M)
            for k in range(0, 25, 5):
                A[j + k] ^= d
        # Rho and pi.
        t = A[1]
        for j in range(24):
            A[PILN[j]], t = ((t << ROTC[j]) | (t >> (64 - ROTC[j]))) & M, A[PILN[j]]
        # Chi.
        for j in range(0, 25, 5):
            C = A[j : j + 5]
            for k in range(5):
                A[j + k] = (C[k] ^ (~C[(k + 1) % 5] & C[(k + 2) % 5])) & M
        # Iota.
        A[0] ^= RC[ir]

    for i in range(25):
        state[8 * i : 8 * i + 8] = A[i].to_bytes(8, "little")
```
<!-- end:code:ref/keccak.py:keccak_p1600 -->

### Integer and String Encodings

`left_encode` and `encode_string` follow NIST SP 800-185. `length_encode` follows RFC 9861: for $`x = 0`$ it returns a
single `0x00` byte rather than `0x00 0x01`. TW128 only calls `length_encode` with $`n \geq 2`$, so the difference is
unreachable in practice.

<!-- begin:code:ref/encodings.py:encodings_all -->
```python
def length_encode(x: int) -> bytes:
    """RFC 9861 length_encode: big-endian, no leading zeros, followed by byte count."""
    if x == 0:
        return b"\x00"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big") + bytes([n])

def left_encode(x: int) -> bytes:
    """Byte count, then big-endian value (at least one byte)."""
    if x == 0:
        return b"\x01\x00"
    n = (x.bit_length() + 7) // 8
    return bytes([n]) + x.to_bytes(n, "big")

def right_encode(x: int) -> bytes:
    """Big-endian value (at least one byte), then byte count."""
    if x == 0:
        return b"\x00\x01"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big") + bytes([n])

def encode_string(x: bytes) -> bytes:
    """SP 800-185: left_encode(len(x) * 8) || x."""
    return left_encode(len(x) * 8) + x
```
<!-- end:code:ref/encodings.py:encodings_all -->

## Appendix C. Deployment Budgeting Across TW128, TurboSHAKE, and KangarooTwelve (Non-Normative)

This appendix is operational guidance for practitioners combining multiple Keccak-based components in one system.
It is not part of the normative algorithm definition.

### C.1 Why this matters

The security bounds in Section 6 include a capacity birthday bound term:

```math
\varepsilon_{\mathrm{cap}} = \frac{(\sigma + t)^2}{2^{c+1}}.
```
This is the simplest conservative estimate for combined online ($`\sigma`$) and offline ($`t`$) Keccak-p call budgets.
For tighter per-key planning under the MRV15 keyed-sponge framework, use $`\varepsilon_{\mathrm{ks}}`$ from Section 6.2,
which provides beyond-birthday-bound security for the keyed setting.

When a deployment uses multiple Keccak-based components under related security assumptions, a conservative practice is
to budget their Keccak-p calls together rather than treating each component in isolation.

### C.2 Practitioner workflow

For a chosen operational window (for example, per key epoch, per process lifetime, or per day), define:

```text
sigma_total = sigma_tw128 + sigma_turboshake + sigma_k12 + sigma_other_keccak
```

where each term is the count of online Keccak-p[1600,12] calls made by that component in the window.
This is the same $`\sigma_{\mathrm{total}}`$ counter model used normatively in Section 7.3.

Then evaluate:

```math
\varepsilon_{\mathrm{cap}} = \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}}
```
for your selected adversary offline budget $`t`$.

Use this as a planning control:

- if $`\varepsilon_{\mathrm{cap}}`$ is below your target risk threshold, the window budget is acceptable;
- if not, shorten the window (rotate keys/state sooner), reduce throughput per key, or separate workloads across keys.

### C.3 What implementers should instrument

At minimum, log per-window counters for:

- TW128 calls and message sizes (convert via Appendix A's per-query formula),
- TurboSHAKE/KangarooTwelve calls and absorbed lengths,
- key/epoch identifiers to support budget resets at rotation boundaries.

This enables straightforward capacity planning and post-incident verification of whether configured limits were
exceeded.

### C.4 Practical default

For most deployments, this budget is generous. The value of tracking it is not that limits are usually tight, but that:

- the system has an explicit, reviewable safety margin,
- key-rotation policy is tied to measurable cryptographic workload,
- mixed-component deployments avoid silent overuse assumptions.
