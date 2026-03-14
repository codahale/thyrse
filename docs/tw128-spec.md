# TW128: Tree-Parallel Authenticated Encryption

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.11</td></tr>
  <tr><th>Date</th><td>2026-03-12</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

TW128 is an authenticated-encryption scheme with associated data (AEAD) built on the duplex construction using the
Keccak-p[1600,12] permutation. It accepts a 256-bit key and a variable-length nonce, and produces a 256-bit
authentication tag, providing 128-bit security for both confidentiality (IND-CCA2) and integrity, with strong multi-user
security and full committing security (CMT-4).

The construction is optimized for two regimes: low latency on short messages, where the single-pass duplex dominates,
and high throughput on long messages, where a one-level tree of parallel leaves can exploit SIMD parallelism. Tree
parallelism is a performance optimization; a correct implementation may process all chunks sequentially. The sole
primitive, Keccak-p[1600,12], is software-friendly and requires no hardware acceleration, making TW128 suitable for
targets ranging from embedded devices to server-class machines.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 2. Parameters

| Symbol   | Value             | Description                                         |
|----------|-------------------|-----------------------------------------------------|
| f        | Keccak-p[1600,12] | per RFC 9861, 1600-bit state, 12 rounds             |
| C        | 32                | Capacity (bytes)                                    |
| R        | 168               | Sponge rate (bytes); $`1600/8 - 32 = 168`$          |
| $`\tau`$ | 32                | Tag size (bytes)                                    |
| $`K_L`$  | 32                | Key length (bytes)                                  |
| B        | 8192              | Chunk size (bytes)                                  |

## 3. Dependencies

TW128 depends on the Keccak-p[1600,12] permutation.

**`Keccak-p[1600,12]`:** The 12-round Keccak permutation on a 1600-bit state, as defined in RFC 9861. This is the
underlying permutation for the duplex construction.

## 4. Duplex

The duplex construction operates on the Keccak-p[1600,12] permutation at rate R = 168 and capacity C = 32. It
provides four operations: `_duplex_pad_permute` applies multi-rate padding with a caller-supplied domain separation
byte and permutes; `_duplex_encrypt` and `_duplex_decrypt` produce ciphertext/plaintext by XORing against the rate
and overwriting with ciphertext; `_duplex_absorb` XOR-absorbs data into the rate. Full-rate blocks permute without
padding; only `_duplex_pad_permute` applies padding. `keccak_p1600` is defined in Appendix B.

<!-- begin:code:ref/duplex.py:duplex_all -->
```python
from collections import namedtuple

R = 168   # Sponge rate (bytes).
C = 32    # Capacity (bytes).

# S: 200-byte Keccak state (bytearray). pos: current offset into the rate.
_DuplexState = namedtuple("_DuplexState", ["S", "pos"])

def _duplex_pad_permute(D: _DuplexState, domain_byte: int) -> _DuplexState:
    """Apply multi-rate padding with domain separation and permute. Resets pos to 0."""
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


## 5. Construction

### 5.1 Notation

- `||`: Byte string concatenation.
- `LEU64(i)`: The 8-byte little-endian encoding of integer `i`.
- `left_encode(x)`: The integer `x` encoded as a byte string prefixed with its own byte-length (NIST SP 800-185).
- `encode_string(x)`: `left_encode(len(x) * 8) || x`. Self-delimiting encoding of a byte string (NIST SP 800-185).
- `length_encode(x)`: The integer `x` encoded as a byte string suffixed with its own byte-length (RFC 9861).

Python reference implementations of these encodings are given in Appendix B.

### 5.2 Initialization

The key, nonce, and associated data are encoded as `encode_string(K) || encode_string(N) || encode_string(AD)` and
absorbed into a fresh duplex state to form the **base state**. The `encode_string` framing makes this encoding
injective: distinct `(K, N, AD)` triples always produce distinct absorption streams. Each tree node clones the base
state and diverges by additionally absorbing a distinct `LEU64(index)` followed by `_duplex_pad_permute(0x08)`,
producing an independent per-node initial state.

### 5.3 Tree Topology

TW128 uses the Sakura final-node-growing topology with kangaroo hopping, following KangarooTwelve (ePrint
2016/770, Sections 1 and 3.3). The input is split into $`n`$ chunks of up to B bytes each.

A single **final node** (index 0) encrypts chunk 0 and produces the authentication tag. When $`n = 1`$,
this is the entire construction: the final node processes the message and squeezes the tag directly.

When $`n > 1`$, chunks 1 through $`n-1`$ are each assigned to an independent **leaf node**. Each leaf
encrypts its chunk and produces a C-byte chain value. The leaf operations are independent and may execute
in parallel. The final node encrypts chunk 0, then absorbs the chain values from all leaves — incrementally,
as they become available — together with the Sakura framing, and squeezes the tag.

### 5.4 Domain Separation

TW128 uses four domain separation bytes, passed to `_duplex_pad_permute`:

| Byte   | Usage                           | Sakura suffix | Node type |
|--------|---------------------------------|---------------|-----------|
| `0x08` | Initialization                  | `000`         | inner     |
| `0x0B` | Leaf chain value                | `110`         | inner     |
| `0x07` | Tag, n=1 (single final)         | `11`          | final     |
| `0x06` | Tag, n>1 (chaining final)       | `01`          | final     |

Each domain byte stores a variable-length suffix bit-string LSB-first, with a delimiter `1` bit immediately after the
last suffix bit. The last suffix bit encodes the Sakura node type: `1` for final nodes, `0` for inner/leaf nodes.
Inner-node bytes use 3-bit suffixes (delimiter at bit 3); final-node bytes use 2-bit suffixes (delimiter at bit 2).
The final node's tag domain byte (`0x06` or `0x07`) is distinct from all leaf domain bytes (`0x08`, `0x0B`).

| Domain byte | Binary | Suffix (LSB-first) | Last bit | Node type |
|-------------|--------|-------------------|----------|-----------|
| `0x08` | 0000 1**000** | `000` | 0 | inner (duplex init) |
| `0x0B` | 0000 1**011** | `110` | 0 | inner (chain value) |
| `0x07` | 0000 0**111** | `11` | 1 | final (tag, n=1) |
| `0x06` | 0000 0**110** | `01` | 1 | final (tag, n>1) |

Inner/final node separability follows directly from Sakura Lemma 4: the final-node bytes (`0x07`, `0x06`) have last suffix bit `1`, while all inner/leaf bytes (`0x08`, `0x0B`) have last suffix bit `0`. Three of the four domain bytes (`0x0B`, `0x07`, `0x06`) are reused directly from KangarooTwelve's Sakura encoding.

**Design constraint.** Future modifications to domain byte assignments MUST preserve Sakura delimited-suffix encoding compliance and the node-type partition between inner and final roles.

### 5.5 Internal Functions

`_leaf_encrypt` and `_leaf_decrypt` each clone the base state, initialize a node at a given index, process one chunk, and return the output data along with a $`c`$-byte chain value.

<!-- begin:code:ref/tw128.py:internal_functions -->
```python
def _leaf_encrypt(base: _DuplexState, index: int, chunk: bytes) -> tuple[bytes, bytes]:
    """Encrypt a leaf chunk, returning (ciphertext, chain_value)."""
    L = _DuplexState(bytearray(base.S), base.pos)
    L = _duplex_absorb(L, index.to_bytes(8, "little"))
    L = _duplex_pad_permute(L, 0x08)
    L, ct = _duplex_encrypt(L, chunk)
    L = _duplex_pad_permute(L, 0x0B)
    return ct, bytes(L.S[:C])

def _leaf_decrypt(base: _DuplexState, index: int, chunk: bytes) -> tuple[bytes, bytes]:
    """Decrypt a leaf chunk, returning (plaintext, chain_value)."""
    L = _DuplexState(bytearray(base.S), base.pos)
    L = _duplex_absorb(L, index.to_bytes(8, "little"))
    L = _duplex_pad_permute(L, 0x08)
    L, pt = _duplex_decrypt(L, chunk)
    L = _duplex_pad_permute(L, 0x0B)
    return pt, bytes(L.S[:C])
```
<!-- end:code:ref/tw128.py:internal_functions -->

Decryption produces the same tag as encryption because both `_duplex_encrypt` and `_duplex_decrypt` overwrite
the rate with ciphertext, yielding identical state evolution (see Section 6.8).

### 5.6 EncryptAndMAC / DecryptAndMAC

**`TW128.EncryptAndMAC(K, N, AD, M) -> (ct, tag)`**\
**`TW128.DecryptAndMAC(K, N, AD, ct) -> (pt, tag)`**

`K` MUST be exactly K_L bytes of uniformly random key material. `N` MUST NOT be reused for the same `(K, AD)` pair.

`encrypt_and_mac` and `decrypt_and_mac` each build a base state from $`(K, N, AD)`$, split the message into $`B`$-byte chunks, and encrypt or decrypt chunk 0 on the final node. For single-chunk messages the final node produces the tag directly. For multi-chunk messages, each remaining chunk is processed by an independent leaf node whose chain value is absorbed into the final node, followed by the Sakura suffix and tag extraction. Both functions return the ciphertext (or plaintext) and the tag as separate values.

**Caller obligations.** `EncryptAndMAC` and `DecryptAndMAC` are the fundamental operations; callers are responsible for the following:

- **IND-CPA:** The caller MUST NOT reuse `(K, N, AD)` with different messages. Each unique combination of key, nonce, and associated data MUST encrypt at most one message.
- **IND-CCA2:** The caller MUST verify the tag (using constant-time comparison) before releasing or acting on the plaintext returned by `DecryptAndMAC`. `DecryptAndMAC` returns unverified plaintext — the caller MUST NOT act on it before verifying the tag.
- **CMT-4:** No additional caller obligation. CMT-4 committing security follows from TW128's structural properties (Section 6).

<!-- begin:code:ref/tw128.py:core_functions -->
```python
import hmac

K_L = 32  # Key length (bytes).
TAU = 32  # Tag size (bytes).
B = 8192  # Chunk size (bytes).

# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def encrypt_and_mac(K: bytes, N: bytes, AD: bytes, M: bytes) -> tuple[bytes, bytes]:
    """Encrypt, returning (ciphertext, tag) as separate values."""
    assert len(K) == K_L, "K must be exactly 32 bytes"

    n = max(1, -(-len(M) // B))
    chunks = [M[i * B : (i + 1) * B] for i in range(n)]

    # Build base state from context prefix.
    prefix = encode_string(K) + encode_string(N) + encode_string(AD)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Initialize and encrypt on the final node.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, ct0 = _duplex_encrypt(F, chunks[0])

    if n == 1:
        F = _duplex_pad_permute(F, 0x07)
        return ct0, bytes(F.S[:TAU])

    # Multi-node: absorb hop frame, process leaves, absorb chain values.
    F = _duplex_absorb(F, HOP_FRAME)
    out_parts = [ct0]
    for i, chunk in enumerate(chunks[1:], start=1):
        ct_i, cv = _leaf_encrypt(base, i, chunk)
        out_parts.append(ct_i)
        F = _duplex_absorb(F, cv)

    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])

def decrypt_and_mac(K: bytes, N: bytes, AD: bytes, ct: bytes) -> tuple[bytes, bytes]:
    """Decrypt without tag verification, returning (unverified_plaintext, tag)."""
    assert len(K) == K_L, "K must be exactly 32 bytes"

    n = max(1, -(-len(ct) // B))
    chunks = [ct[i * B : (i + 1) * B] for i in range(n)]

    # Build base state from context prefix.
    prefix = encode_string(K) + encode_string(N) + encode_string(AD)
    base = _duplex_absorb(_DuplexState(bytearray(200), 0), prefix)

    # Initialize and decrypt on the final node.
    F = _DuplexState(bytearray(base.S), base.pos)
    F = _duplex_absorb(F, (0).to_bytes(8, "little"))
    F = _duplex_pad_permute(F, 0x08)
    F, pt0 = _duplex_decrypt(F, chunks[0])

    if n == 1:
        F = _duplex_pad_permute(F, 0x07)
        return pt0, bytes(F.S[:TAU])

    # Multi-node: absorb hop frame, process leaves, absorb chain values.
    F = _duplex_absorb(F, HOP_FRAME)
    out_parts = [pt0]
    for i, chunk in enumerate(chunks[1:], start=1):
        pt_i, cv = _leaf_decrypt(base, i, chunk)
        out_parts.append(pt_i)
        F = _duplex_absorb(F, cv)

    F = _duplex_absorb(F, length_encode(n - 1) + SAKURA_SUFFIX)
    F = _duplex_pad_permute(F, 0x06)
    return b"".join(out_parts), bytes(F.S[:TAU])
```
<!-- end:code:ref/tw128.py:core_functions -->

### 5.7 AEAD Wrappers

**`TW128.Encrypt(K, N, AD, M) -> ct || tag`**\
**`TW128.Decrypt(K, N, AD, ct || tag) -> M | None`**

`tw128_encrypt` and `tw128_decrypt` provide a standard AEAD interface for the underlying `encrypt_and_mac` and `decrypt_and_mac` functions. `tw128_encrypt` concatenates the ciphertext and tag; `tw128_decrypt` splits the input, calls `decrypt_and_mac`, verifies the tag with constant-time comparison, and returns the plaintext or `None`.

<!-- begin:code:ref/tw128.py:aead_functions -->
```python
def tw128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    """AEAD encryption: returns ct ‖ tag."""
    ct, tag = encrypt_and_mac(K, N, AD, M)
    return ct + tag

def tw128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    """AEAD decryption: verifies tag and returns plaintext or None."""
    if len(ct_tag) < TAU:
        return None
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(K, N, AD, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
```
<!-- end:code:ref/tw128.py:aead_functions -->

## 6. Security Properties

This section gives a complete reduction from TW128 AEAD security to the ideal-permutation assumption on
Keccak-p[1600,12]. It is organized as follows:

- **Sections 6.1–6.4** establish the model, justify the ideal-permutation assumption, cite supporting
  external results (MRV15, ADMV15, PRP/PRF switching), and verify that TW128's construction
  satisfies their preconditions.
- **Sections 6.5–6.8** prove structural lemmas: encoding injectivity, context independence, exact
  uniformity of construction π-outputs, and per-node structural properties (bijection, state equivalence).
- **Sections 6.9–6.13** decompose TW128 into a bare-game framework grounded in exact uniformity
  and reduce each AEAD goal (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) to structural properties.
- **Section 6.14** collects all bounds into a summary table.

All bounds are in the ideal-permutation model for Keccak-p[1600,12], with capacity $`c = 256`$ bits and $`\tau = 32`$
tag bytes. Nonce-misuse resistance is explicitly out of scope: all IND-CPA and IND-CCA2 claims assume a nonce-respecting
adversary. Related-key security is also out of scope: all claims assume the master key $`K`$ is uniformly random and
independent of any other keys in the system.

### 6.1 Model and Notation

Let:

- $`\sigma`$: total online Keccak-p calls by the construction across all queries.
- $`t`$: adversary offline Keccak-p calls ($`\pi`$ and $`\pi^{-1}`$ evaluations in the ideal-permutation model).
- $`S`$: total number of decryption/verification forgery attempts.
- $`n = \max(1, \lceil |M|/B \rceil)`$: number of chunks for a message of length $`|M|`$.
- Throughout Section 6, $`c = 8C = 256`$ denotes the capacity in bits.

Unless stated otherwise, these symbols are scoped to one fixed master key (one key epoch / one experiment instance).
Section 6.13 (CMT-4) is an exception: the adversary controls the keys in that game. Section 7.3 provides guidance
on choosing $`t`$ for bound evaluation.

### 6.2 Ideal-Permutation Assumption

Concrete bounds in this section are conditional on Keccak-p[1600,12] behaving as an ideal
permutation. This is a modeling assumption, not a proof about reduced-round Keccak-p itself.
If this assumption fails, the security analysis that follows does not apply.

Public cryptanalysis on Keccak-family primitives includes reduced-round results with explicit round counts.
On standard Keccak-224/256 instances: practical 4-round collisions and 5-round near-collisions (Hamming
distance 5–10) are reported in DDS14. On reduced-capacity contest instances (Keccak[c=160]): 6-round
collision solutions are publicly reported (Keccak Crunchy Crypto Contest). In the raw-permutation setting
(Keccak-f[1600] with full state access, no keying): differential distinguishers reach 8 rounds at
complexity $`2^{491.47}`$ (DGPW11), and zero-sum distinguishers reach 16 rounds (of the original 18) at
complexity $`2^{1023.88}`$ (AM09). All known results above 6 rounds are in the unkeyed raw-permutation
setting and require state access or control that the keyed duplex does not provide.
(See the Keccak Team third-party table and reduced-round references in Section 8.)

These results do not directly invalidate the TW128 security analysis because TW128 uses a
keyed duplex setting with 256-bit capacity and strict domain separation;
nevertheless, future cryptanalysis could narrow the practical margin, so deployments should treat the
concrete bounds as conditional.

### 6.3 Preliminary Results

**Capacity birthday bound.** Define:

```math
\varepsilon_{\mathrm{cap}} \;\stackrel{\mathrm{def}}{=}\; \frac{(\sigma + t)^2}{2^{c+1}}.
```

Let $`\mathsf{Bad}_{\mathrm{perm}}`$ be the event that two distinct Keccak-p evaluations (among all $`\sigma + t`$
online and offline calls) produce equal capacity portions, or that any evaluation produces a capacity portion
equal to the initial capacity $`0^c`$. By the birthday bound,
$`\Pr[\mathsf{Bad}_{\mathrm{perm}}] \leq \varepsilon_{\mathrm{cap}}`$. This term appears in every final bound
in Section 6.14.

**PRP/PRF switching.** The ideal permutation samples without replacement. Throughout Section 6, "uniform" and
"independent" outputs from $`\pi`$ on distinct inputs are understood modulo the PRP/PRF switching distance
$`\sigma^2 / 2^{1601}`$, which is negligible compared to $`\varepsilon_{\mathrm{cap}}`$ for $`c = 256 \ll 1600`$. This cost
is not repeated in individual theorem statements.

**Keyed duplex (MRV15).** The following theorem provides per-node PRF bounds; Section 6.4 verifies that
TW128 satisfies its preconditions. This result is not used in the AEAD proofs (Sections 6.9–6.12), which
derive their conclusions from exact uniformity (Section 6.7); it is used for the tag-as-PRF property
(Section 7.3).

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

Due to Mennink, Reyhanitabar, and Vizár (Asiacrypt 2015).

**Outer-keyed sponge (ADMV15).** TW128 absorbs the key into the rate rather than placing it directly in the
capacity. ADMV15 (Andreeva, Daemen, Mennink, and Van Assche, FSE 2015) proves PRF security for this
outer-keyed sponge construction $`\mathrm{Sponge}(K \| M)`$, confirming that rate-absorbed key loading is
sound in the ideal-permutation model. Section 6.4 verifies the applicability to TW128's key-loading.
The quantitative cost of key secrecy is charged directly in the bare-game decomposition (Section 6.9)
via the freshness analysis (Section 6.7), rather than through the ADMV15 composite bound.

### 6.4 MRV15 Applicability

This section verifies that TW128 satisfies the preconditions of MRV15 Theorem 2 (FKD). This verification
is not used in the AEAD proofs (Sections 6.9–6.12); it is used for the tag-as-PRF property (Section 7.3)
and for per-key capacity planning (Appendix C).

TW128 nodes are keyed duplexes: the overwrite encrypt/decrypt operation fuses
a squeeze of keystream with an absorption of plaintext in a single duplexing
call, which requires the duplex's bidirectional interface. This matches MRV15's
Full Keyed Duplex (FKD) model.

The parameters are $`b = 1600`$, $`c = 256`$, $`k = c = 256`$. Each
leaf is a single duplex evaluation ($`q = 1`$), so at the per-leaf level the FKD
bound simplifies to $`\ell^2/2^b + \ell^2/2^c + \mu N/2^k`$, and
$`\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)`$ captures the advantage for leaf $`i`$
with $`l_i`$ duplexing calls.

**Key-loading: outer-keyed sponge.** MRV15's FKD initializes with the key placed
directly in the capacity portion of the state: $`S \gets 0^{b-k} \| K`$. TW128
instead absorbs the key into the rate via standard sponge absorption — the
outer-keyed sponge construction $`\mathrm{Sponge}(K \| M)`$. ADMV15 (Section 6.3)
confirms that this construction is PRF-secure in the ideal-permutation model.
For the bare-game analyses, the key-secrecy property is charged directly via
the freshness analysis (Section 6.7): each init $`\pi`$-input contains the secret
key in the rate, so an adversary's offline query matches with probability at most
$`1/2^k`$. The init call is accounted for in $`\mu`$.

**Overwrite-mode equivalence.** MRV15 assumes XOR-absorb. TW128 uses overwrite mode, but the two produce
identical state evolution: $`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ followed by
$`S[\mathit{pos}] \gets \mathit{ct}[j]`$ yields the same state byte as
$`S[\mathit{pos}] \mathrel{\oplus}= \mathit{pt}[j]`$. Ciphertext bytes are a deterministic, invertible
function of FKD-modeled rate outputs, so no additional information is revealed.
BDPVA11 (Algorithm 5, Theorem 2) provides independent confirmation.

**Squeeze-phase coverage.** MRV15's FKD includes explicit squeeze output at each
duplexing call. TW128's tags ($`\tau = 32`$ bytes) and chain values
($`C = 32`$ bytes) are single-block squeezes well within one rate block
($`R = 168`$ bytes). These outputs are directly covered by Theorem 2.

### 6.5 Domain Separation Lemma

**Lemma (Domain separation).** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ (Section 6.3), the construction's $`\pi`$-calls partition into disjoint sets by role, such that no two calls from different roles share a full 1600-bit input.

| Set | Role | Domain byte | Distinguishing mechanism |
|-----|------|-------------|--------------------------|
| $`\mathcal{I}`$ | Duplex init | `0x08` | Padded, domain byte `0x08` |
| $`\mathcal{C}`$ | Chain value | `0x0B` | Padded, domain byte `0x0B` |
| $`\mathcal{T}_s`$ | Single-node tag | `0x07` | Padded, domain byte `0x07` |
| $`\mathcal{T}_f`$ | Chaining-hop tag | `0x06` | Padded, domain byte `0x06` |
| $`\mathcal{U}`$ | Unpadded intermediate | — | Secret capacity from keyed init |

*Proof sketch.* The core argument is: padded calls with different domain bytes differ in rate content; all other cross-role pairs differ in their capacity portion under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$.

1. **Padded vs. padded (different domain bytes).** Each `_duplex_pad_permute` call XORs its domain byte at offset `pos` in the rate. If two calls share the same `pos`, the different domain bytes produce different rate content. If they differ in `pos`, they must also differ in capacity: non-init padded calls ($`\mathcal{C}`$, $`\mathcal{T}_s`$, $`\mathcal{T}_f`$) inherit capacity from prior $`\pi`$-outputs, which are pairwise distinct under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$. Only init calls ($`\mathcal{I}`$) start from zero capacity, and within a single context all init calls reach `_duplex_pad_permute` at the same `pos`, so cross-init pairs fall under the same-`pos` case — distinct indices ensure distinct rate content.

2. **Padded vs. unpadded.** Unpadded intermediate calls ($`\mathcal{U}`$) inherit capacity from prior $`\pi`$-outputs. So do non-init padded calls. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ these inherited capacities are pairwise distinct. Init calls start from zero capacity; under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ no inherited capacity equals $`0^c`$.

3. **Within a set.** Cross-instance: distinct absorption streams (different `encode_string` prefixes or different `LEU64(index)` values) produce distinct rate content at init, propagating through the capacity chain. Within-instance: each call inherits the previous call's capacity portion, pairwise distinct under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$. Both mechanisms apply to $`\mathcal{U}`$.

**Consequence.** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, each role's $`\pi`$-calls are functionally independent of every other role's. This is the precondition for Section 6.6 (context independence), Sections 6.9–6.12 (bare-game analyses), and Section 6.13 (CMT-4 commitment analysis).

### 6.6 Context Independence

**Lemma (Context independence).** Distinct `(K, N, AD, index)` tuples produce distinct init $`\pi`$-inputs.

**Context encoding.** Each $`(K, N, AD)`$ triple defines a *context*. The context encoding is:

```math
X = \mathrm{encode\_string}(K)\,\|\,\mathrm{encode\_string}(N)\,\|\,\mathrm{encode\_string}(AD).
```
Distinct triples produce distinct $`X`$ values (by injectivity of `encode_string`).

**Base-state construction.** The context prefix $`X`$ is absorbed into a fresh duplex state via standard XOR-absorb.
Each tree node clones this base state, absorbs `LEU64(index)`, and calls `_duplex_pad_permute(0x08)`. The full π-input
for the init call of node $`(K, N, AD, i)`$ is therefore determined by the absorption of
$`X \| \mathrm{LEU64}(i)`$ into a fresh state, followed by `0x08`-padding.

**Argument.**

1. **`encode_string` injectivity.** Distinct `(K, N, AD)` triples produce distinct $`X`$ values.
   Appending distinct `LEU64(i)` values within the same context, or using distinct contexts,
   produces distinct absorption streams $`X \| \mathrm{LEU64}(i)`$. Therefore every
   `(K, N, AD, i)` tuple yields a distinct pre-padding rate content.

2. **Domain separation (Section 6.5).** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, init π-calls (set
   $`\mathcal{I}`$, domain byte `0x08`) are on inputs disjoint from all other roles' π-calls. Distinct
   init π-inputs therefore produce distinct init π-outputs, and these outputs are functionally
   independent of all other construction components.

No context-collision term is needed: `encode_string` injectivity is exact (not probabilistic),
and node-index distinctness is structural. The quantitative cost of key secrecy (preventing adversary
offline queries from coinciding with init π-inputs) is charged once in the bare-game decomposition
(Section 6.9) via the freshness analysis (Section 6.7).

**Consequence.** Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ and adversary-query freshness, each node's init
state is exactly uniform and independent of all other nodes' init states and of all non-init construction
components. This is the structural precondition for the bare-game analyses in Sections 6.10–6.12.
CMT-4 (Section 6.13) is a multi-key notion with a standalone proof that does not use this argument.

### 6.7 Exact Uniformity

In the ideal-permutation model, conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$, every $`\pi`$-call on a fresh (never-before-seen) 1600-bit input produces a truly
uniform 1600-bit output — not merely computationally pseudorandom. Freshness has two components:

1. **Among construction calls.** $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ ensures pairwise distinct capacity portions, and the
   Domain Separation Lemma (Section 6.5) ensures distinct rate contents across roles. Together these guarantee no two
   construction $`\pi`$-calls share a full 1600-bit input.
2. **With respect to adversary offline queries.** An adversary $`\pi/\pi^{-1}`$ query may coincide with a construction
   call's input. The match probability per query depends on which secret component prevents collision:

   | Call type | Secret component | Match probability |
   |---|---|---|
   | Init ($`\mathcal{I}`$) | Key in rate | $`\le 1/2^k`$ |
   | Intermediate | Capacity from prior $`\pi`$-output | $`\le 1/2^c`$ |

   Since $`k = c = 256`$ for TW128, the total freshness-failure probability is at most $`\mu\, t / 2^c`$.
   This cost is charged in the bare-game decomposition (Section 6.9).

Conditioned on both $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ and adversary-query freshness, all construction $`\pi`$-outputs
are exactly uniform. This principle is the engine for the bare-bound analyses in Sections 6.10–6.12: once both conditions
are accounted for, the remaining advantage reduces to structural collision and forgery probabilities over truly uniform
values.

### 6.8 Per-Node Structural Lemmas

**Overwrite-mode equivalence.** Overwrite mode and XOR-absorb of plaintext produce identical state evolution:
$`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ followed by
$`S[\mathit{pos}] \gets \mathit{ct}[j]`$ yields the same state byte as
$`S[\mathit{pos}] \mathrel{\oplus}= \mathit{pt}[j]`$. Both lemmas below depend on this equivalence.

**Lemma 1 (Fixed-key bijection).**
For a fixed init state and message length, encrypt is a bijection on the message space. Each ciphertext byte
$`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ uniquely determines $`\mathit{pt}[j]`$ given the state,
and state evolution is direction-independent (overwrite-mode equivalence), so decrypt inverts encrypt exactly.
Each chunk is processed by an independent node, so the full $`n`$-node encrypt is also a bijection between
equal-length plaintexts and ciphertexts. This is used in Section 6.13 (CMT-4).

**Lemma 2 (Encrypt/decrypt state equivalence).**
Decrypt produces the same tag as encrypt because both write the same ciphertext bytes into the rate
(overwrite-mode equivalence). This holds for all nodes: each leaf produces the same chain value under
encrypt and decrypt, and the final node absorbs the same chain values and squeezes the same tag.

### 6.9 Bare-Game Framework

All analyses in Sections 6.10–6.12 work conditioned on
$`\neg\mathsf{Bad}_{\mathrm{perm}}`$ (Section 6.3) and adversary-query freshness (Section 6.7).
The cost of $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ ($`\varepsilon_{\mathrm{cap}}`$) and freshness failure
($`\mu\, t / 2^c`$) are each charged once and do not recur.
(CMT-4, Section 6.13, is a multi-key notion with a standalone bound.)

Define the **bare advantage** $`\mathrm{Adv}_{\Pi}^{\mathrm{bare}}`$ as the adversary's advantage against the
construction conditioned on both $`\neg\mathsf{Bad}_{\mathrm{perm}}`$ and adversary-query freshness. Under these
conditions, every construction $`\pi`$-call is on a fresh input and therefore produces an exactly uniform output
(Section 6.7).

Each AEAD property's total advantage decomposes as:

```math
\mathrm{Adv}_{\Pi} \le \varepsilon_{\mathrm{cap}} + \frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}.
```
where $`\mu`$ is the total absorbed blocks across all keyed construction
evaluations (base-state prefix absorption plus leaf and final-node duplexing calls). The $`\mu\, t / 2^k`$ term
is the freshness-failure probability from Section 6.7: each of the $`\mu`$ construction $`\pi`$-inputs contains
a secret component (key in rate for init calls, inherited capacity for intermediate calls) that an adversary
offline query matches with probability at most $`1/2^k = 1/2^c`$, over $`t`$ offline queries.

### 6.10 IND-CPA (Nonce-Respecting)

```
Game IND-CPA_b(A):
  K <-$ {0,1}^{|K|}
  b' <- A^{Enc_b}
  return b'

Oracle Enc_b(N, AD, M0, M1):
  require |M0| = |M1|
  return TW128.Encrypt(K, N, AD, M_b)
```

**Claim.** $`\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} = 0`$.

*Justification.* Under the bare-game conditioning (Section 6.9), every construction $`\pi`$-output is exactly
uniform. Each ciphertext byte $`\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]`$ is therefore a one-time pad:
$`S[\mathit{pos}]`$ is exactly uniform and plaintext-independent. Overwrite mode writes $`\mathit{ct}[j]`$ (not
$`\mathit{pt}[j]`$) into the state, so subsequent state evolution — including the tag-squeeze input — depends
only on the ciphertext, not the plaintext choice. Since the ciphertext distribution is uniform regardless of
which message was encrypted, so is the tag. For n > 1, leaves operate on independent init states (domain
separation, Section 6.5; context independence, Section 6.6), so the same reasoning applies to each chunk
independently.

The total bound follows from the decomposition in Section 6.9.

### 6.11 INT-CTXT

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

*Justification.* Under the bare-game conditioning (Section 6.9), every construction $`\pi`$-output is exactly
uniform. A forgery must either target a different context or the same context with a modified ciphertext.

A different context produces an independent init state (Section 6.6) and therefore an independent, exactly
uniform tag. For the same context, any change to the ciphertext alters the input to at least one $`\pi`$-call
in the tag's dependency chain: a different ciphertext byte changes the rate via overwrite mode; a different
length shifts absorption boundaries or changes the `length_encode` suffix; crossing the n=1/n>1 boundary
changes the tag domain byte (`0x07` vs `0x06`).

The altered $`\pi`$-input is fresh (bare-game conditioning) and therefore produces an exactly uniform output,
including a fresh capacity portion. Under $`\neg\mathsf{Bad}_{\mathrm{perm}}`$, this fresh capacity is shared by
no other $`\pi`$-input, so the next call in the chain is also fresh; this propagates to the tag-squeeze call,
producing an exactly uniform tag (Section 6.7). For modifications in a leaf chunk, the same mechanism produces a
different chain value, which when absorbed into the final node alters a $`\pi`$-input there, and the cascade
continues to the tag.

Each forgery attempt therefore succeeds with probability at most $`2^{-8\tau}`$. Across $`S`$ attempts (union bound):

```math
\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le \frac{S}{2^{8\tau}}.
```

The total bound follows from the decomposition in Section 6.9.

If tags are truncated to $`T < \tau`$ bytes, replace $`S/2^{8\tau}`$ with $`S/2^{8T}`$.

### 6.12 IND-CCA2 (Nonce-Respecting)

By BN00 Theorem 3.2, any scheme satisfying both IND-CPA and INT-CTXT also satisfies IND-CCA2:

```math
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} + 2\,\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}}.
```

Substituting the bare bounds from Sections 6.10 and 6.11:

```math
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \frac{2S}{2^{8\tau}}.
```

The total bound follows from the decomposition in Section 6.9.

### 6.13 CMT-4

This theorem follows the Bellare–Hoang CMT-4 committing-security notion [BH22, §3]: a ciphertext should not admit
two distinct valid openings under any choice of keys. Unlike the fixed-key properties in Sections 6.10–6.12, this is a
multi-key notion — the adversary controls all inputs including the master keys — and the proof does not flow through
context independence (Section 6.6).

```
Game CMT-4(A):
  (C*, (K, N, AD, M), (K', N', AD', M')) <- A^{pi, pi^{-1}}
  require (K, N, AD, M) != (K', N', AD', M')
  require |M| = |M'|
  return TW128.Encrypt(K, N, AD, M) = C*
     and TW128.Encrypt(K', N', AD', M') = C*
```

The adversary has direct access to the ideal permutation $`\pi`$ and its inverse. Define $`L`$ and $`L'`$ as the base states after absorbing the
`encode_string` prefix for each context.

- **Case 1: same context, different message.** $`(K,N,AD)=(K',N',AD')`$, so $`M \neq M'`$ (since
  full tuples are distinct). Both openings use the same base state and the same chunking
  (equal-length messages). By Lemma 1 (fixed-key bijection, Section 6.8), the encrypt function is a
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
  (distinct base states produce distinct init $`\pi`$-inputs, Section 6.6), the adversary can evaluate at most $`t + \sigma_v`$ candidates within their
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

### 6.14 Summary of Bounds

Each property's total advantage follows the decomposition in Section 6.9:

```math
\mathrm{Adv}_{\Pi} \le \varepsilon_{\mathrm{cap}} + \frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}.
```
| Property | $`\mathrm{Adv}^{\mathrm{bare}}`$ | Total |
|----------|-------------------------------|-------|
| IND-CPA  | $`0`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k`$ |
| INT-CTXT | $`S / 2^{8\tau}`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k + S / 2^{8\tau}`$ |
| IND-CCA2 | $`2S / 2^{8\tau}`$ | $`\varepsilon_{\mathrm{cap}} + \mu\, t / 2^k + 2S / 2^{8\tau}`$ |

CMT-4 (Section 6.13) has a standalone multi-key bound that does not use the bridge decomposition:

```math
\mathrm{Adv}_{\mathrm{CMT\text{-}4}}(\mathcal{A}) \le \frac{(t + \sigma_v)^2}{2^{c+1}} + \frac{t + \sigma_v}{2^{8\tau}}.
```
All symbols as defined in Sections 6.1 and 6.3.

## 7. Operational Security

### 7.1 Side Channels

Implementations MUST be constant-time with respect to secret-dependent control flow and memory access.

- No lookup tables indexed by secret state bytes.
- Tag verification MUST use constant-time equality.
- Partial-block logic may branch on public length, not on secret data.

### 7.2 Nonce Guidance

The $`(K, N, AD)`$ triple MUST NOT be reused: repeating a triple leaks the XOR of the two plaintexts
(Section 6.10). Deterministic nonces (counters or sequences) MUST NOT repeat within a key epoch.

For random nonces, 128 bits is RECOMMENDED. The nonce collision budget follows the birthday bound:
for nonce bit-length $`b_n`$ and $`q`$ encryptions, the collision probability is approximately
$`q^2 / 2^{b_n+1}`$. Longer nonces (192 or 256 bits) proportionally increase the safe encryption count.

### 7.3 Usage Limits (Normative)

To claim the 128-bit security target, deployments MUST enforce per-master-key usage limits (a *key epoch*)
and rotate to a fresh master key before exceeding them.

Implementations MUST maintain the following per-key-epoch counters:

- $`q_{\mathrm{enc}}`$: number of encryption invocations.
- $`\sigma_{\mathrm{total}}`$: all Keccak-p evaluations sharing the same ideal-permutation instance within
  one key epoch (including non-TW128 Keccak uses, if any).
- $`S`$: number of failed decryption/verification attempts (forgery attempts).

Required baseline (MUST):

- Enforce $`\sigma_{\mathrm{total}} \le 2^{60}`$.
- Tag output MUST be at least 16 bytes ($`T \geq \tau/2`$). Truncation below 16 bytes voids the 128-bit
  security target for both INT-CTXT and CMT-4.
- Define and enforce a failed-verification budget $`S_{\mathrm{cap}}`$ per key epoch
  (RECOMMENDED: $`S_{\mathrm{cap}} = 2^{32}`$). On exceedance, rotate to a fresh key epoch.
- On any cap exceedance, implementations MUST rotate to a fresh key epoch before further encryption.

Evaluate the Section 6 bounds using $`t = 2^{64}`$ as the default offline-work parameter. The parameter $`t`$
is an analysis assumption, not an operationally measurable quantity.

**Multi-user security.** For deployments spanning $`U`$ independent master keys, the
$`\mathsf{Bad}_{\mathrm{perm}}`$ event is global (a capacity collision among *any* pair of the system-wide
$`\sigma + t`$ evaluations), so $`\varepsilon_{\mathrm{cap}}`$ is charged once with $`\sigma = \sum_u \sigma_u`$.
The remaining per-key terms are independent across keys and summed via union bound:

```math
\mathrm{Adv}_{\mathrm{multi}} \le \varepsilon_{\mathrm{cap}}(\sigma_{\mathrm{global}}, t) + U \cdot \left(\frac{\mu\, t}{2^k} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}\right).
```

**Example planning table** (collision target $`p = 2^{-50}`$, record size = 1500 bytes):

| Nonce size | Limiting factor  | Approx safe volume per key epoch |
|------------|------------------|----------------------------------|
| 128-bit    | nonce collisions | $`\approx 2^{20}`$ GiB            |
| 192-bit    | nonce collisions | $`\approx 2^{52}`$ GiB            |
| 256-bit    | proof bound      | $`\approx 2^{80}`$ GiB            |

**Tag as PRF output.** TW128's tag is a full PRF output, not just a MAC. The final node is a keyed duplex
evaluation: it encrypts chunk 0, absorbs chain values (if any), and squeezes the tag — all within a single
continuous FKD instance. Section 6.4 verifies that TW128 satisfies MRV15's preconditions (overwrite-mode
equivalence, squeeze within one rate block, outer-keyed sponge initialization). By MRV15 Theorem 2
(Section 6.3), the tag is therefore pseudorandom with advantage at most
$`\varepsilon_{\mathrm{ks}}(1, \ell_f, \ell_f, t)`$, where $`\ell_f`$ is the final node's duplexing-call count.
Protocols that derive further keying material from the tag may rely on this property.

## 8. References

- **[ADMV15]** Andreeva, E., Daemen, J., Mennink, B., and Van Assche, G. "Security of Keyed Sponge Constructions Using
  a Modular Proof Approach." FSE 2015. Proves PRF security of the outer-keyed sponge construction, confirming that
  TW128's rate-absorbed key loading is sound (Section 6.4).
- **[AM09]** Aumasson, J.-P. and Meier, W. "Zero-sum distinguishers for reduced Keccak-f and for the core functions of
  Luffa and Hamsi." 2009. https://www.aumasson.jp/data/papers/AM09.pdf. Presents zero-sum distinguishers up to 16 rounds.
- **[BDPVA11]** Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass
  Authenticated Encryption and Other Applications." SAC 2011. IACR ePrint 2011/499. Defines the duplex construction
  and proves overwrite-mode security (Algorithm 5, Theorem 2). Referenced in Section 6.4.
- **[BDPVA13]** Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing."
  IACR ePrint 2013/231. Defines the tree hash coding framework used by KangarooTwelve and TW128.
- **[BDPVAVK16]** Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B.
  "KangarooTwelve: fast hashing based on Keccak-p." IACR ePrint 2016/770. Security and design context for the
  Sakura-based tree structure.
- **[BDPVAVK23]** Bertoni, G., Daemen, J., Hoffert, S., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B.
  "TurboSHAKE." IACR ePrint 2023/342. Primary specification and design rationale for TurboSHAKE. Referenced in
  Appendix C for system-wide Keccak budgeting; not a TW128 dependency.
- **[BH22]** Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." EUROCRYPT 2022.
  Defines the CMT-4 committing security notion (§3, E-notion with $`\ell = 4`$). Section 6.13 uses this game directly.
- **[BN00]** Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the
  Generic Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2; used in Section 6.12.
- **[DDS14]** Dinur, I., Dunkelman, O., and Shamir, A. "New attacks on Keccak-224 and Keccak-256." FSE 2012; published
  as "Improved practical attacks on round-reduced Keccak" in Journal of Cryptology 27(4), 2014. Reports practical
  4-round collisions and 5-round near-collision results in standard Keccak-224/256 settings.
- **[DGPW11]** Duc, A., Guo, J., Peyrin, T., and Wei, L. "Unaligned Rebound Attack - Application to Keccak." IACR
  ePrint 2011/420. Gives differential distinguishers up to 8 rounds of Keccak internal permutations.
- **[MRV15]** Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex:
  Applications to Authenticated Encryption." Asiacrypt 2015. IACR ePrint 2015/541. Proves beyond-birthday-bound
  PRF security for the full-state keyed duplex (Theorem 2, FKD) in the ideal-permutation model. Used for the
  tag-as-PRF property (Section 7.3).
- **[NIST SP 800-185]** Kelsey, J., Chang, S.-j., and Perlner, R. "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash,
  and ParallelHash." NIST SP 800-185, 2016. https://csrc.nist.gov/pubs/sp/800/185/final. Defines `left_encode`
  and `encode_string`, used by TW128 for injective context encoding.
- **[RFC 9861]** Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B.
  "KangarooTwelve and TurboSHAKE." RFC 9861, 2025. Defines Keccak-p[1600,12], the reduced-round permutation
  used by TW128.
- Keccak Team. "Keccak Crunchy Crypto Collision and Pre-image Contest."
  https://keccak.team/crunchy_contest.html. Public contest record for reduced-round Keccak[c=160] instances, including
  6-round collision solutions.
- Keccak Team. "Third-party cryptanalysis." https://keccak.team/third_party.html. Curated summary table of published
  cryptanalysis results and round counts across Keccak-family modes and raw permutations.

## 9. Test Vectors

All test vectors in this section are for TW128.

<!-- begin:vectors:docs/tw128-test-vectors.json:aead -->
### 9.1 TW128 Vectors

These vectors validate `tw128_encrypt` / `tw128_decrypt` (the TW128 instantiation),
including SP 800-185 `encode_string` context encoding.

#### 9.1.1 Empty Message

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | (empty) |
| M len | 0 |
| ct‖tag | `3b662f3b0a8bf7b6e12ea98994d962640912a92e2ec3352f975b5ddbe2585ea9` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.1.2 33-Byte Message With 5-Byte AD

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `a0 a1 a2 ... ab` |
| AD | 10 11 12 ... 14 |
| M len | 33 (`00 01 02 ... mod 256`) |
| ct‖tag | `2c7f7e2fb779fbf32ee81092375c0066941447c8422cdf2e08cf8f4468fd5c1e0fc8c3ab1ba8815222909e95724a5b51e7cc7a78032f11d674ed57e1dbf6e2224d` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.1.3 Multi-Chunk Message (8193 Bytes)

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

#### 9.1.4 Nonce Reuse Behavior (Equal-Length Messages)

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

#### 9.1.5 Swapped Nonce and AD Domains

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

#### 9.1.6 Empty AD vs One-Byte AD 00

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

#### 9.1.7 Long AD (128 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 21 32 ... ff` |
| N | 12 bytes `ab ab ac ad ae af b0 b1 b2 b3 b4 b5` |
| AD | ab ab ab ... ab |
| M len | 17 (`00 01 02 ... 10`) |
| ct‖tag | `58d9cf0a4c794672fdc1c184a21794df707aa9d1a966fa1dabd2cfad617ef3ea3ce04bbade0bdc8d19dab09182dfc032dd` |

`tw128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.1.8 Rate-Minus-One Message (167 Bytes, R-1 Boundary)

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

#### 9.1.9 Exact-Rate Message (168 Bytes, R Boundary)

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

#### 9.1.10 Large Nonce (32 Bytes)

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

where $`d_f`$ is the number of permutation calls during the final node's tag phase (1 for the tag `_duplex_pad_permute`, plus
any additional calls from absorbing HOP_FRAME, chain values, and the chaining-hop suffix when $`n > 1`$).

More precisely:

- **Base-state prefix term.** $`|\mathit{prefix}|`$ is the byte length of
  `encode_string(K) || encode_string(N) || encode_string(AD)`.
  Each `encode_string` contributes `left_encode(8|x|)` (2-3 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $`|\mathit{prefix}| = (3+32) + (2+12) + (2+0) = 51`$ bytes, giving
  $`\lfloor 51 / 168 \rfloor = 0`$ Keccak-p calls (the prefix fits within a single rate block and the permutation
  occurs at the subsequent `_duplex_pad_permute`, which is counted in the final-node or leaf init).
- **Final node term.** The final node (index 0) costs $`1`$ (init `_duplex_pad_permute`) $`+`$
  $`\lfloor \ell_0 / R \rfloor`$ (unpadded intermediate permutations during chunk-0 encryption) $`+`$ $`d_f`$ (tag phase).
  For $`n = 1`$: $`d_f = 1`$ (one `_duplex_pad_permute(0x07)`). For $`n > 1`$: $`d_f`$ accounts for absorbing the 8-byte HOP_FRAME,
  $`(n-1)`$ chain values of $`C`$ bytes each, the chaining-hop suffix ($`|\mathrm{length\_encode}(n-1)| + 2`$ bytes), and the
  final `_duplex_pad_permute(0x06)`. These are XOR-absorbed contiguously into the rate starting from the position left after
  chunk-0 encryption.
- **Leaf term.** Each leaf (indices $`1, \ldots, n-1`$) costs $`2`$ (init `_duplex_pad_permute` + terminal `_duplex_pad_permute` for
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

<!-- begin:code:ref/encodings.py:encodings_tw128 -->
```python
def length_encode(x: int) -> bytes:
    """RFC 9861 length_encode: big-endian, no leading zeros, followed by byte count."""
    if x == 0:
        return b"\x00"
    n = (x.bit_length() + 7) // 8
    return x.to_bytes(n, "big") + bytes([n])

def left_encode(x: int) -> bytes:
    """NIST SP 800-185 left_encode: byte count, then big-endian value (at least one byte)."""
    if x == 0:
        return b"\x01\x00"
    n = (x.bit_length() + 7) // 8
    return bytes([n]) + x.to_bytes(n, "big")

def encode_string(x: bytes) -> bytes:
    """NIST SP 800-185 encode_string: left_encode(len(x) * 8) || x."""
    return left_encode(len(x) * 8) + x
```
<!-- end:code:ref/encodings.py:encodings_tw128 -->

## Appendix C. Deployment Budgeting Across TW128, TurboSHAKE, and KangarooTwelve (Non-Normative)

This appendix is operational guidance for practitioners combining multiple Keccak-based components in one system.
It is not part of the normative algorithm definition.

### C.1 Why this matters

The security bounds in Section 6 include a capacity birthday bound term:

```math
\varepsilon_{\mathrm{cap}} = \frac{(\sigma + t)^2}{2^{c+1}}.
```
This is the simplest conservative estimate for combined online ($`\sigma`$) and offline ($`t`$) Keccak-p call budgets.
For tighter per-key planning under the MRV15 keyed-sponge framework, use $`\varepsilon_{\mathrm{ks}}`$ from Section 6.4,
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

## Appendix D. Implementation Design Callouts (Non-Normative)

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
  base-state cloning pattern are structural for interoperability and security analysis.

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
