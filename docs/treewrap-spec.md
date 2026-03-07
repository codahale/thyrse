# TreeWrap128: Tree-Parallel Authenticated Encryption

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.10</td></tr>
  <tr><th>Date</th><td>2026-03-05</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

TreeWrap128 is an authenticated-encryption scheme with associated data (AEAD) built on Keccak-p[1600,12]. It uses a
TurboSHAKE128-based key derivation to produce a per-invocation key, then encrypts via a Sakura flat-tree topology that
enables SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. The final node encrypts the first chunk directly, then
absorbs chain values from parallel leaves that process subsequent chunks, producing a single MAC tag.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 2. Parameters

| Symbol | Value             | Description                                           |
|--------|-------------------|-------------------------------------------------------|
| f      | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds)    |
| R      | 168               | Sponge rate (bytes)                                   |
| C      | 32                | Capacity (bytes); key and chain value size            |
| $\tau$ | 32                | Tag size (bytes); equal to C for this instantiation   |
| B      | 8192              | Chunk size (bytes), matching KangarooTwelve           |

**Parameter constraints.** $C + 8 \leq R - 1$ (init material `key || LEU64(index)` = $C + 8 = 40$ bytes fits in a
single rate block). $\max(\tau, C) < R$ (tag and chain value outputs fit in a single squeeze block).

## 3. Dependencies

**`TurboSHAKE128(M, D, l)`:** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01 - 0x7F),
and an output length `l` in bytes.

## 4. Duplex

The duplex operates on a standard Keccak sponge with the same permutation and rate/capacity parameters as
TurboSHAKE128. The `domain_byte` parameter to `_duplex_pad_permute` is supplied by the caller; Section 5 defines
the five domain separation bytes used by TreeWrap128.

Unlike the XOR-absorb approach used by SpongeWrap, the `encrypt` and `decrypt` operations write ciphertext directly
into the rate rather than XORing plaintext into it. This is the Overwrite-mode style analyzed in Bertoni et al.
(Section 6.2, Algorithm 5; Theorem 2) and used in Section 6. Intermediate (non-final) encrypt/decrypt blocks fill the
full R = 168 byte rate and permute without padding; only terminal operations (initialization, chain value finalization, and the tag
`_duplex_pad_permute` in `EncryptAndMAC`/`DecryptAndMAC`) apply TurboSHAKE-style padding via `pad_permute`. For full-rate
blocks, a write-only state update is also faster than read-XOR-write on most architectures.

> **Rate distinction.** Initialization absorbs at effective rate R-1 = 167 bytes: padding (domain byte at `pos`,
> `0x80` at position R-1) requires one byte reserved for the domain/padding frame, so `pad_permute` triggers when `pos`
> reaches R-1. Intermediate encrypt/decrypt blocks use the full R = 168 byte rate with no padding overhead, permuting
> via raw `keccak_p1600` when `pos` reaches R. Terminal operations (chain value finalization and the tag `_duplex_pad_permute`) call
> `pad_permute` at whatever `pos` the final partial block leaves, accommodating both full and partial final blocks.

The duplex is defined by the following reference implementation. `keccak_p1600` and `turboshake128` are defined in
Appendix B.

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

> [!NOTE]
> `_duplex_pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at $R-1$). Initialization
> uses domain byte `0x08`; chain value finalization uses `0x0B`; the tag `_duplex_pad_permute` in
> `EncryptAndMAC`/`DecryptAndMAC` uses `0x07` (n=1) or `0x06` (n>1). Intermediate encrypt/decrypt blocks use the full
> $R = 168$ byte rate and permute without padding (`keccak_p1600` directly), matching standard unpadded sponge absorb
> for non-final blocks. Both `_duplex_encrypt` and `_duplex_decrypt` overwrite the rate with ciphertext, so state
> evolution is identical regardless of direction. `_duplex_absorb` XOR-absorbs data into the rate without padding,
> permuting via raw `keccak_p1600` when the rate is full. Chain value finalization calls `_duplex_pad_permute` to mix
> all data before squeezing; the output fits in a single squeeze block since $C = 32 \ll R = 168$.

## 5. TreeWrap128

### Notation

- `||`: Byte string concatenation.
- `LEU64(i)`: The 8-byte little-endian encoding of integer `i`.

The encodings used here (`left_encode`, `encode_string`, `length_encode`) are defined as Python functions in Appendix B.
`left_encode` and `encode_string` follow NIST SP 800-185; `length_encode` follows RFC 9861.

### Tree Topology

TreeWrap128 uses the Sakura final-node-growing topology with kangaroo hopping, following KangarooTwelve (ePrint
2016/770, Sections 1 and 3.3). The final node (index 0) is a duplex that encrypts chunk 0 directly (the "message
hop"). Chunks 1 through $n-1$ are processed by independent leaf Duplexes that produce chain values (the "chaining hop").

For $n = 1$, the final node encrypts the entire message and produces the tag via `pad_permute(0x07)`. The Sakura frame
bits are: message hop `'1'` + final `'1'` = `'11'`, yielding domain byte `0x07` (delimited suffix `'111'`).

For $n > 1$, the final node is a duplex that:

1. Inits with `key || LEU64(0)` via `pad_permute(0x08)`.
2. Encrypts chunk 0 (the message hop).
3. Absorbs `HOP_FRAME` (`0x03 || 0x00^7`), the Sakura message-hop / chaining-hop framing.
4. Absorbs chain values $\mathit{cv}_1 \;\|\; \cdots \;\|\; \mathit{cv}_{n-1}$.
5. Absorbs `length_encode(n-1) || 0xFF || 0xFF`.
6. Calls `pad_permute(0x06)` and squeezes the $\tau$-byte tag.

The transition from overwrite-mode encryption (step 2) to XOR-mode absorption (step 3) does not require a permutation:
the overwrite-mode equivalence (Lemma 2 in Section 6) ensures that the sponge state after encrypting chunk 0 is
identical to the state that would result from XOR-absorbing the same ciphertext. Both modes resume from the same
`pos` offset.

The Sakura frame bits at the tag are: chaining hop `'0'` + final `'1'` = `'01'`, yielding domain byte `0x06`
(delimited suffix `'011'`). The fields above are:

- **`HOP_FRAME`** (8 bytes): the Sakura message-hop / chaining-hop frame `'110^{62}'` packed LSB-first as `0x03 || 0x00^7`.
- **`cv_i`** (C = 32 bytes each): the chain value squeezed from leaf $i$ (for $i = 1, \ldots, n-1$).
- **`length_encode(n-1)`**: the Sakura coded nrCVs field encoding the number of chain values ($n-1$, since the final
  node handles chunk 0), encoded per RFC 9861.
- **`0xFF || 0xFF`**: the Sakura interleaving block size encoding $I = \infty$ (no block interleaving); mantissa and
  exponent both `0xFF`.

Each domain byte stores a variable-length suffix bit-string LSB-first, with a delimiter `1` bit immediately after the
last suffix bit. The last suffix bit encodes the Sakura node type: `1` for final nodes, `0` for inner/leaf nodes. The
inner-node bytes use 3-bit suffixes (delimiter at bit 3): init (`0x08`, suffix `'000'`), chain value (`0x0B`, suffix
`'110'`), and KDF (`0x09`, suffix `'100'`). The final-node bytes use 2-bit suffixes (delimiter at bit 2): chaining-hop
tag (`0x06`, suffix `'01'`) and single-node tag (`0x07`, suffix `'11'`). Final-node separability follows directly from
the last suffix bit: `1` for final, `0` for inner.

The `0xFF || 0xFF` suffix is defined as `SAKURA_SUFFIX` in the reference code (Section 5.1).

The following table summarizes the five domain separation bytes used by TreeWrap128:

| Byte   | Usage                           | Sakura suffix | Node type |
|--------|---------------------------------|---------------|-----------|
| `0x07` | Tag, n=1 (single final)         | `11`          | final     |
| `0x06` | Tag, n>1 (chaining final)       | `01`          | final     |
| `0x0B` | Leaf chain value                | `110`         | inner     |
| `0x08` | Init (key/index absorption)     | `000`         | inner     |
| `0x09` | AEAD key derivation             | `100`         | inner     |

**Domain separation.** The key is in the sponge state via `init` (domain byte `0x08`), not prepended to an input
string. Both the final node and every leaf call `init(key, index)` with distinct indices: the final node uses index 0,
while leaves use indices $1, \ldots, n-1$. The final node's tag domain byte (`0x06` or `0x07`) is distinct from all
leaf domain bytes (`0x08`, `0x0B`), providing an additional layer of separation.

**Encoding injectivity.** The chaining-hop suffix `length_encode(n-1) || 0xFF || 0xFF` is self-delimiting: `0xFF`
cannot be a valid `length_encode` byte-count (chain-value counts fit in at most 8 bytes), so the interleaving block
size bytes are unambiguously terminal, and the byte immediately preceding them gives the byte-count of $n-1$. Given
$n-1$, the chain values are parsed as $n-1$ consecutive $C$-byte blocks following the `HOP_FRAME`.

### 5.1 Internal Functions: EncryptAndMAC / DecryptAndMAC

The internal encrypt-and-MAC functions take a per-invocation key and plaintext (or ciphertext), and return the processed
data and a MAC tag. These functions are not intended to be called directly; TreeWrap128 (Section 5.2) wraps them with key
derivation and tag verification.

**`EncryptAndMAC(key, plaintext) -> (ciphertext, tag)`**\
**`DecryptAndMAC(key, ciphertext) -> (plaintext, tag)`**

*Inputs:*

- `key`: A C-byte key. MUST be pseudorandom (computationally indistinguishable from uniform) and unique per invocation
  (no two calls share a key).
- `plaintext` / `ciphertext`: Data of any length (may be empty). Maximum length is $(2^{64} - 1) \cdot B$ bytes, since
  leaf indices are encoded as 8-byte little-endian integers.

*Outputs:*

- `ciphertext` / `plaintext`: Same length as the input data.
- `tag`: A $\tau$-byte MAC tag.

*Procedure:*

```python
# Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first.
HOP_FRAME = bytes([0x03]) + bytes(7)

# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def _tree_process(key: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for EncryptAndMAC / DecryptAndMAC."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    op = _duplex_encrypt if direction == "E" else _duplex_decrypt

    # Final node: absorb key || LEU64(0) and pad to key the duplex.
    F = _DuplexState(bytearray(200), 0)
    F = _duplex_absorb(F, key + (0).to_bytes(8, "little"))
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
        # Absorb key || LEU64(i) and pad to key the leaf duplex.
        L = _DuplexState(bytearray(200), 0)
        L = _duplex_absorb(L, key + i.to_bytes(8, "little"))
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

def encrypt_and_mac(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, plaintext, "E")

def decrypt_and_mac(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, ciphertext, "D")
```

The final node (index 0) always encrypts chunk 0. Leaf operations for chunks 1 through $n-1$ are independent and may
execute in parallel. Tag computation begins as soon as all chain values are available. `decrypt_and_mac` produces the
same tag as `encrypt_and_mac` because both `encrypt` and `decrypt` write ciphertext into the sponge rate (Section 4).

> [!CAUTION]
> For production implementations, avoid repeated byte-string concatenation (`final_input += ...`) when building the
> final node input; prefer preallocation or list/join style buffer construction.

### 5.2 TreeWrap128 Encrypt / Decrypt

TreeWrap128 derives a per-invocation key from `(K, N, AD)` using TurboSHAKE128, then delegates to
`EncryptAndMAC`/`DecryptAndMAC`.

**`TreeWrap128.Encrypt(K, N, AD, M) -> ct || tag`**\
**`TreeWrap128.Decrypt(K, N, AD, ct || tag) -> M | None`**

**Master-key requirement.** `K` MUST be a uniformly random 32-byte (256-bit) key.

**Key derivation:**

```
tw_key <- TurboSHAKE128(encode_string(K) || encode_string(N) || encode_string(AD), 0x09, C)
```

The `encode_string` encoding (NIST SP 800-185) makes the concatenation injective: each field is prefixed with its
`left_encode`d bit-length (`left_encode(8*len(x))`), so no `(K, N, AD)` triple can produce the same TurboSHAKE128 input
as a different triple. Domain byte `0x09` separates key derivation from all other TreeWrap128 domain bytes
(`0x08`, `0x0B`, `0x07`, `0x06`).

```python
import hmac

def treewrap128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    assert len(K) == C, "K must be exactly 32 bytes"
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x09, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    assert len(K) == C, "K must be exactly 32 bytes"
    if len(ct_tag) < TAU:
        return None
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x09, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
```

## 6. Security Properties

This section gives a complete reduction from TreeWrap128 AEAD security to the ideal-permutation assumption on
Keccak-p[1600,12]. The argument has two layers:

- **Layer A (Section 6.4).** A single game hop replaces the TurboSHAKE128 KDF with a lazy random function, using the
  MRV15 keyed-sponge PRF framework (FKS, Section 6.2) to bound the distinguishing advantage.
- **Layer B (Sections 6.6–6.10).** Under random keys, each AEAD goal (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) decomposes
  into keyed-duplex PRF properties of the leaf ciphers (FKD, Section 6.2): pseudorandomness of rate outputs,
  structural state equivalence, and fixed-key bijection.

All bounds are in the ideal-permutation model for Keccak-p[1600,12], with capacity $c = 256$ bits and $\tau = 32$ tag
bytes. Nonce-misuse resistance is explicitly out of scope: all IND-CPA and IND-CCA2 claims assume a nonce-respecting
adversary. Related-key security is also out of scope: all claims assume the master key $K$ is uniformly random and
independent of any other keys in the system.

> [!CAUTION]
> **Nonce reuse is catastrophic.** Reusing the same $(K, N, AD)$ triple with different equal-length
> messages produces identical keystreams, leaking the XOR of all plaintexts (two-time pad). This
> enables full plaintext recovery given one known plaintext. Nonce uniqueness per $(K, AD)$ pair is a
> hard security requirement (Section 7.4), not a quality-of-implementation concern.

**Length leakage.** TreeWrap128 ciphertexts reveal the exact plaintext length: `|ct| = |M|` (plus the
fixed $\tau$-byte tag). This is inherent to any stream-cipher-based AEAD and is not mitigated by this
construction. Applications requiring length hiding must pad plaintexts before encryption.

**Assumption scope.** Concrete bounds in this section are conditional on Keccak-p[1600,12] behaving as an ideal
permutation at the claimed workloads. This is a modeling assumption, not a proof about reduced-round Keccak-p itself.

> [!IMPORTANT]
> Public cryptanalysis on Keccak-family primitives includes reduced-round results with explicit round counts: practical
> collision-style results are publicly known through 5 rounds in standard Keccak instances, with 6-round collision
> solutions publicly reported for reduced-round contest instances, and structural distinguishers are known at higher
> round counts in the raw-permutation setting (including 8-round distinguishers and 16-round zero-sum distinguishers).
> (See the Keccak Team third-party table and reduced-round references in Section 9.)
>
> These results do not directly invalidate the TreeWrap128 heuristic because TreeWrap128 uses a keyed sponge/duplex setting
> with 256-bit capacity, strict domain separation, and workload limits; nevertheless, future cryptanalysis could change
> the practical margin, so deployments should treat the concrete bounds as conditional.

### 6.1 Model and Notation

Let:

- $\sigma$: total online Keccak-p calls performed by the construction across all oracle queries
  (including KDF, leaf-sponge, and chaining-hop tag permutation calls).
- $t$: adversary offline Keccak-p calls (an analysis parameter representing direct access to the ideal
  permutation $\pi$ in the ideal-permutation model, not a deployment-controlled quantity; Section 7.4 provides
  operational guidance on choosing $t$ for bound evaluation).
- $S$: total number of decryption/verification forgery attempts in one security experiment (per key epoch).
- $Q$: total number of AEAD outputs (encryption-oracle responses plus any outputs the adversary compares in a forgery or
  commitment game) in one security experiment (per key epoch); each encryption-oracle response (ciphertext + tag) counts
  as one AEAD output. Used in birthday-style collision bounds.
- $q_{\mathrm{ctx}}$: number of distinct context strings $X$ queried to the KDF in one security experiment.
- $n = \max(1, \lceil |M|/B \rceil)$: number of chunks for a message of length $|M|$.
- Throughout Section 6, $c = 8C = 256$ denotes the capacity in bits.

Define:

$$
\varepsilon_{\mathrm{cap}} \;\stackrel{\mathrm{def}}{=}\; \frac{(\sigma + t)^2}{2^{c+1}}.
$$

This is the capacity birthday bound. Let $\mathsf{Bad}_{\mathrm{perm}}$ be the event that the ideal permutation
exhibits a capacity-part collision among any pair of the $\sigma + t$ total evaluations (online construction calls and
adversary offline calls). A *capacity-part collision* occurs when two distinct Keccak-p evaluations produce equal
256-bit capacity outputs (the low $c$ bits of the 1600-bit state). By the birthday bound,
$\Pr[\mathsf{Bad}_{\mathrm{perm}}] \leq \binom{\sigma+t}{2} \cdot 2^{-c} \leq \varepsilon_{\mathrm{cap}}$.

Let $\varepsilon_{\mathrm{ks}}(q, \ell, \mu, N)$ denote the MRV15 PRF advantage bound for $q$ keyed-sponge or
keyed-duplex evaluations of at most $\ell$ input blocks (or duplexing calls) each, $\mu$ total blocks across all
evaluations ($\mu \leq q\ell$), and $N$ adversary offline $\pi$-queries. MRV15 Theorems 1 (FKS) and 2 (FKD) yield
bounds of the same three-term structure but with different capacity terms; see Section 6.2.

**PRP/PRF switching.** The ideal permutation samples without replacement. Throughout Section 6, "uniform" and
"independent" outputs from $\pi$ on distinct inputs are understood modulo the PRP/PRF switching distance
$\sigma^2 / 2^{1601}$, which is negligible compared to $\varepsilon_{\mathrm{cap}}$ for $c = 256 \ll 1600$. This cost
is not repeated in individual theorem statements.

Throughout this section, "capacity state," "capacity output," and "capacity projection" all refer to the 256-bit
low-order portion of the 1600-bit Keccak-p state.

**Exact uniformity under $\neg\mathsf{Bad}_{\mathrm{perm}}$.** In the ideal-permutation model, conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}}$, every $\pi$-call on a fresh (never-before-seen) 1600-bit input produces a truly
uniform 1600-bit output — not merely computationally pseudorandom. Since $\neg\mathsf{Bad}_{\mathrm{perm}}$ ensures all
capacity outputs are pairwise distinct, and the Domain Separation Lemma (Section 6.3) ensures rate contents are distinct
across roles, each construction $\pi$-call has a fresh input. Outputs are therefore exactly uniform. This principle is
the engine for all bare-bound analyses in Sections 6.7–6.10: once $\neg\mathsf{Bad}_{\mathrm{perm}}$ is conditioned
away (at cost $\varepsilon_{\mathrm{cap}}$), the remaining advantage reduces to structural collision and forgery
probabilities over truly uniform values.

Unless stated otherwise, these symbols are scoped to one fixed master key (one key epoch / one experiment instance).

### 6.2 Keyed-Duplex PRF Framework (MRV15)

TreeWrap128 leaf ciphers are keyed duplexes: after initialization, each leaf
interleaves absorb and squeeze operations (absorb plaintext block → permute →
squeeze keystream/tag). This matches MRV15's Full Keyed Duplex (FKD) model
rather than the single-evaluation Full Keyed Sponge (FKS). The two theorems
yield bounds of different form in the capacity term.

**Theorem (MRV15, Theorem 2 — FKD).** Let $\mathrm{FKD}^{\pi}_K$ be the
full-state keyed duplex instantiated with an ideal permutation $\pi$ on $b$
bits, capacity $c$, and key length $k$. For an adversary making $q$ duplex
evaluations, each consisting of at most $\ell$ duplexing calls, $\mu \leq q\ell$
total duplexing calls across all evaluations, and $N$ offline $\pi$-queries:

$$
\mathrm{Adv}^{\mathrm{ind}}_{\mathrm{FKD}^{\pi}_K,\,\pi}(q, \ell, \mu, N)
  \;\leq\;
  \frac{(q\ell)^2}{2^b}
  \;+\; \frac{(q\ell)^2}{2^c}
  \;+\; \frac{\mu N}{2^k}.
$$

**Theorem (MRV15, Theorem 1 — FKS).** Let $\mathrm{FKS}^{\pi}_K$ be the
full-state keyed sponge with the same parameters. For an adversary making $q$
sponge evaluations of at most $\ell$ input blocks each, $\mu \leq q\ell$ total
blocks, and $N$ offline $\pi$-queries:

$$
\mathrm{Adv}^{\mathrm{ind}}_{\mathrm{FKS}^{\pi}_K,\,\pi}(q, \ell, \mu, N)
  \;\leq\;
  \frac{2(q\ell)^2}{2^b}
  \;+\; \frac{2q^2\ell}{2^c}
  \;+\; \frac{\mu N}{2^k}.
$$

Both theorems are due to Mennink, Reyhanitabar, and Vizár (Asiacrypt 2015).
The structural difference is in the capacity term: FKD has $(q\ell)^2 / 2^c$
(scaling with $q^2\ell^2$), while FKS has $2q^2\ell / 2^c$ (scaling with
$q^2\ell$). FKS thus provides a tighter capacity bound per query when $\ell$ is
large.

For TreeWrap128 the parameters are $b = 1600$, $c = 256$, $k = c = 256$. Each
leaf is a single duplex evaluation ($q = 1$), so at the per-leaf level the FKD
bound simplifies to $\ell^2/2^b + \ell^2/2^c + \mu N/2^k$, and
$\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)$ captures the advantage for leaf $i$
with $l_i$ duplexing calls. With $q = 1$ the capacity terms of FKD and FKS
coincide up to a factor of 2 ($\ell^2/2^c$ vs.\ $2\ell/2^c$; for $\ell \geq 2$
FKD is actually looser). The KDF sponge (Section 6.4) is a single-evaluation
keyed sponge covered by MRV15 Theorem 1 (FKS).

**Term analysis for TreeWrap128.** The FKD bound has three terms:

1. **Full-state birthday** $\frac{(q\ell)^2}{2^{1600}}$: negligible at
   $b = 1600$. Even for $q\ell = 2^{128}$ this term is below $2^{-1344}$.

2. **Online-vs-online capacity term** $\frac{(q\ell)^2}{2^{256}}$: scales with
   $q^2\ell^2$. For TreeWrap128 *leaves* with $q = 1$, this simplifies to
   $\ell^2/2^{256}$. With $\ell \approx 49$ blocks per full 8192-byte chunk
   ($\lfloor 8192/168 \rfloor + 1$), the per-leaf capacity term is
   $49^2 / 2^{256} \approx 2^{-244.8}$, which is negligible. For the *KDF*
   sponge (FKS, Theorem 1), the capacity term is instead $2q^2\ell / 2^c$,
   which scales with $q^2\ell$ rather than $q^2\ell^2$ — an $\ell$-factor
   improvement over the FKD form — and is the dominant online-online term in
   the multi-query KDF setting.

3. **Online-vs-offline term** $\frac{\mu N}{2^{256}}$: dominant when the
   adversary's offline computation budget $N$ (denoted $t$ elsewhere in this
   document) is significant. This term is linear in the total absorbed block
   count $\mu$ rather than quadratic. It is identical in FKS and FKD.

**Key-loading: outer-keyed sponge.** MRV15's FKD initialises with the key placed
in the capacity portion of the state: $S \gets 0^{b-k} \| K$. TreeWrap128
instead absorbs the key into the rate via standard sponge absorption: the
byte-string $K \| \mathrm{LEU64}(\mathit{index})$ is XOR'd into rate positions,
followed by pad-and-permute with domain byte $\mathtt{0x08}$. This is the
*outer-keyed sponge* construction $\mathrm{Sponge}(K \| M)$. Andreeva, Daemen,
Mennink, and Van Assche (ADMV15, FSE 2015) prove PRF security of both inner-
and outer-keyed sponges using a modular proof approach, obtaining bounds of the
same form as MRV15. After the init permutation call, the full state is
$\pi(K \| \mathit{index} \| \mathtt{0x08}\text{-pad} \| 0^c)$; since $K$ is
secret and uniform, this $\pi$-input is unique with overwhelming probability,
and the resulting state is uniformly random over the adversary's view. The
subsequent duplex operation proceeds from this uniform state, which is exactly
the precondition for MRV15's internal proof. The init call is accounted for in
$\mu$ (total absorbed blocks).

**Overwrite-mode coverage.** MRV15 structurally assumes XOR-absorb. TreeWrap128's
encrypt operation produces identical state evolution:
$\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]$ followed by
$S[\mathit{pos}] \gets \mathit{ct}[j]$ yields the same state byte as
$S[\mathit{pos}] \mathrel{\oplus}= \mathit{pt}[j]$, since
$\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]$ in both paths.
Overwrite mode is therefore algebraically identical to XOR-absorb for state
evolution. The ciphertext bytes the adversary observes are precisely the rate
outputs (post-overwrite state bytes), which is the information MRV15 models as
observable duplex output; no additional leakage occurs. BDPVA11 (Algorithm 5,
Theorem 2) provides independent confirmation of overwrite-mode security.

**Squeeze-phase coverage.** MRV15's FKD includes explicit squeeze output at each
duplexing call. TreeWrap128's tags ($\tau = 32$ bytes) and chain values
($C = 32$ bytes) are single-block squeezes well within one rate block
($R = 168$ bytes). These outputs are directly covered by Theorem 2.

> [!NOTE]
> The BDPVA07 flat sponge claim gives a generic
> $N^2 / 2^{c+1}$ bound (where $N$ is total permutation calls) for the unkeyed sponge setting, which
> yields $(\sigma + t)^2 / 2^{c+1}$ in the online/offline decomposition used here. MRV15 provides
> tighter bounds for the keyed setting that TreeWrap128 exclusively uses.
> BDPVA07 remains valid as a fallback analysis but is superseded here. For the
> KDF (FKS, Theorem 1), the principal improvement is that the online-vs-online
> term scales with $q^2\ell$ rather than $q^2\ell^2$, eliminating a factor of
> $\ell$ from the dominant birthday-like term. For leaves (FKD, Theorem 2),
> the capacity term is $(q\ell)^2/2^c$, which has the same $q^2\ell^2$ scaling
> as the birthday bound but with $q = 1$ per leaf the term reduces to
> $\ell^2/2^c$, still well below the global BDPVA07 bound.

### 6.3 Domain Separation Lemma

**Lemma (Domain separation).** Under $\neg\mathsf{Bad}_{\mathrm{perm}}$ (Section 6.1), the construction's $\pi$-calls partition into disjoint sets by role, such that no two calls from different roles share a full 1600-bit input.

| Set | Role | Domain byte | Distinguishing mechanism |
|-----|------|-------------|--------------------------|
| $\mathcal{K}$ | KDF | `0x09` | Padded, domain byte `0x09` |
| $\mathcal{I}$ | Duplex init | `0x08` | Padded, domain byte `0x08` |
| $\mathcal{C}$ | Chain value | `0x0B` | Padded, domain byte `0x0B` |
| $\mathcal{T}_s$ | Single-node tag | `0x07` | Padded, domain byte `0x07` |
| $\mathcal{T}_f$ | Chaining-hop tag | `0x06` | Padded, domain byte `0x06` |
| $\mathcal{U}$ | Unpadded intermediate | — | Secret capacity from keyed init |

*Proof sketch.* Three cases:

1. **Padded vs. padded (different domain bytes).** The domain byte occupies a fixed position in the TurboSHAKE padding frame (byte position `pos` in `pad_permute`). Two padded blocks with different domain bytes differ in that byte position, hence have different rate content and different full $\pi$-inputs regardless of capacity.

2. **Padded vs. unpadded.** Unpadded intermediate blocks (set $\mathcal{U}$) carry no domain byte or `0x80` padding. Their capacity inputs are inherited from the keyed init chain: the initial capacity is zero; after the init `pad_permute`, the capacity output is nonzero with overwhelming probability (it is the capacity projection of $\pi$ on a fresh input); each subsequent $\pi$-call inherits the previous call's capacity output. Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, all capacity outputs are pairwise distinct across the $\sigma + t$ evaluations. The only $\pi$-call with zero capacity input is the initial state (used exclusively by padded init calls), so no unpadded block's capacity input can equal any padded block's capacity input. Combined with the rate-content difference (unpadded blocks lack domain bytes and `0x80` padding), the full 1600-bit $\pi$-inputs are distinct.

3. **Within a set.** Calls within the same role are distinguished by either different keys (different rate content at init) or different capacity inputs inherited from prior calls in the chain (guaranteed distinct under $\neg\mathsf{Bad}_{\mathrm{perm}}$).

**Sakura suffix structure.** The domain bytes are not arbitrary constants. Each encodes a Keccak delimited suffix (ePrint 2013/231) using the standard encoding: a variable-length suffix bit-string is stored LSB-first in the byte, with a delimiter `1` bit immediately after the last suffix bit. The inner-node bytes (`0x08`, `0x0B`, `0x09`) use 3-bit suffixes (delimiter at bit 3), while the final-node bytes (`0x07`, `0x06`) use 2-bit suffixes (delimiter at bit 2). All follow the Keccak delimited-suffix convention. The last suffix bit encodes the Sakura node type: `0` for inner/leaf, `1` for final.

| Domain byte | Binary | Suffix (LSB-first) | Last bit | Node type |
|-------------|--------|-------------------|----------|-----------|
| `0x08` | 0000 1**000** | `000` | 0 | inner (duplex init) |
| `0x0B` | 0000 1**011** | `110` | 0 | inner (chain value) |
| `0x09` | 0000 1**001** | `100` | 0 | inner (KDF) |
| `0x07` | 0000 0**111** | `11` | 1 | final (tag, n=1) |
| `0x06` | 0000 0**110** | `01` | 1 | final (tag, n>1) |

Inner/final node separability follows directly from Sakura Lemma 4: the final-node bytes (`0x07`, `0x06`) have last suffix bit `1`, while all inner/leaf bytes (`0x08`, `0x0B`, `0x09`) have last suffix bit `0`. Three of the five domain bytes (`0x0B`, `0x07`, `0x06`) are reused directly from KangarooTwelve's Sakura encoding, providing established cross-protocol semantics.

**Design constraint.** Future modifications to domain byte assignments MUST preserve Sakura delimited-suffix encoding compliance and the node-type partition between inner and final roles.

**Consequence.** Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, each role's $\pi$-calls are functionally independent of every other role's. This is the precondition for Section 6.4 (KDF replacement in isolation) and Sections 6.6–6.10 (independent leaf, tag, and commitment analysis).

### 6.4 Bridge Theorem: KDF to Random Key

This section executes the single game hop that replaces the TurboSHAKE128 KDF with a lazy random function, using the
MRV15 framework (Section 6.2) and domain separation (Section 6.3).

**Context encoding and derived-key map.** Define the AEAD context encoding:

$$
X = \mathrm{encode\_string}(K)\,\|\,\mathrm{encode\_string}(N)\,\|\,\mathrm{encode\_string}(AD),
$$

and the derived-key map:

$$
F(X) = \mathrm{TurboSHAKE128}(X,\;\mathtt{0x09},\;C).
$$

**Games.**

```
Game G0(A):                          Game G1(A):
  K <-$ {0,1}^{8C}                     K <-$ {0,1}^{8C}
  b <-$ {0,1}                          b <-$ {0,1}
  b' <- A^{Enc,Dec}                    b' <- A^{Enc,Dec}
  return b'                            return b'

Enc/Dec use:                         Enc/Dec use:
  X <- ES(K)||ES(N)||ES(AD)           X <- ES(K)||ES(N)||ES(AD)
  tw_key <- TS128(X, 0x09, C)         tw_key <- R(X)
  [proceed with tw_key]               [proceed with tw_key]
```

Where $\mathrm{ES} = \mathrm{encode\_string}$, $\mathrm{TS128} = \mathrm{TurboSHAKE128}$, $R$ is a lazy random
function $\{0,1\}^* \to \{0,1\}^{8C}$. The adversary's oracle access depends on the security goal (encryption oracle
for IND-CPA, encryption + decryption oracles for IND-CCA2, encryption + forgery oracle for INT-CTXT/CMT-4). The game
hop replaces only the KDF; all oracles and winning conditions are otherwise identical to the standard definitions.

**Hop justification.**

1. **Domain separation (Section 6.3).** Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, the KDF's $\pi$-calls (set
   $\mathcal{K}$, domain byte `0x09`) are on inputs disjoint from all other components' $\pi$-calls. The KDF sponge
   evaluation is therefore functionally independent of the leaf ciphers and final-node Duplex.

2. **MRV15 keyed-sponge PRF (Section 6.2).** The KDF is a single-evaluation keyed sponge (absorb context, squeeze
   once) with uniformly random master key $K$. By the outer-keyed sponge result (ADMV15, Section 6.2), after the
   init permutation the state is uniformly random. MRV15 Theorem 1 (FKS) applies: the KDF's output on distinct
   context strings $X$ is indistinguishable from a PRF with advantage at most
   $\varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t)$, where
   $q_{\mathrm{ctx}}$ is the number of distinct contexts, $\ell_{\mathrm{kdf}}$ is the maximum number of input blocks
   per KDF call, and $\mu_{\mathrm{kdf}}$ is the total KDF input blocks.

3. **PRF-to-RF switching.** By the standard PRF-RF switching lemma, a PRF with $q_{\mathrm{ctx}}$ queries is
   indistinguishable from a lazy random function with advantage at most
   $\varepsilon_{\mathrm{ctx\text{-}coll}} \le q_{\mathrm{ctx}}^2 / 2^{8C+1}$
   (the collision probability among $q_{\mathrm{ctx}}$ uniform $8C$-bit outputs).

**Bound:**

$$
\left|\Pr[\mathsf{G}_0=1]-\Pr[\mathsf{G}_1=1]\right| \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}},
$$

where $\varepsilon_{\mathrm{cap}}$ covers $\mathsf{Bad}_{\mathrm{perm}}$ (needed for domain separation),
$\varepsilon_{\mathrm{ks}}$ is the MRV15 PRF bound for the KDF, and
$\varepsilon_{\mathrm{ctx\text{-}coll}} = q_{\mathrm{ctx}}^2 / 2^{8C+1}$ covers derived-key collisions.

Let $\mathsf{CtxColl}$ denote the event of a derived-key collision among distinct contexts. This context-collision term
is per experiment/per key epoch.

> [!NOTE]
> The MRV15-based approach replaces the indifferentiability composition argument (MRH/CDMP) used in earlier versions of
> this analysis. Because MRV15 is a direct PRF result in the ideal-permutation model, no composition theorem is needed,
> and the Ristenpart-Shacham-Shrimpton (RSS11) multi-stage caveat does not arise.

**Summary.** All AEAD goals below (Sections 6.7–6.10) are analyzed in $\mathsf{G}_1$, conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. Section 6.5 defines the bare-game framework and the
total-advantage decomposition used by all subsequent sections.

### 6.5 Bare-Game Framework

All analyses in Sections 6.6–6.10 work in $\mathsf{G}_1$ (Section 6.4) conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. The costs of these events
($\varepsilon_{\mathrm{cap}}$ and $\varepsilon_{\mathrm{ctx\text{-}coll}}$) are charged once in the bridge theorem
and do not recur.

Define the **bare advantage** $\mathrm{Adv}_{\Pi}^{\mathrm{bare}}$ as the adversary's advantage against the internal
functions under independent uniformly random per-context keys, conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$. Each
AEAD property's total advantage decomposes as:

$$
\mathrm{Adv}_{\Pi} \le \underbrace{\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t)}_{\text{bridge hop (Section 6.4)}} + \underbrace{\varepsilon_{\mathrm{ctx\text{-}coll}}}_{\text{key collision}} + \underbrace{\mathrm{Adv}_{\Pi}^{\mathrm{bare}}}_{\text{Sections 6.7–6.10}}.
$$

Under the exact uniformity principle (Section 6.1), all bare-bound analyses reduce to structural collision and forgery
probabilities over truly uniform values.

### 6.6 Leaf Security Lemmas

Assume a fixed, uniformly random, secret key $K_{tw} \in \{0,1\}^{8C}$.

**Lemma 1 (Keyed-duplex pseudorandomness).**
For any keyed duplex initialized with `K_tw || LEU64(i)` (where $K_{tw}$ is a uniformly random secret key and $i$ is a
public index), in the ideal-permutation model, the PRF advantage distinguishing the rate outputs (keystream bytes and
terminal squeeze bytes) from uniformly random is at most $\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)$, where $l_i$ is the
number of duplexing calls for leaf $i$ and $t$ is the adversary offline Keccak-p budget (Section 6.1). This holds for both overwrite-mode
absorption (used during encryption) and standard XOR-mode absorption (used during framing and chain-value absorption in the final node).

*Proof.* Each leaf is a keyed duplex with uniformly random key $K_{tw}$ (from $\mathsf{G}_1$). By the Domain Separation
Lemma (Section 6.3), under $\neg\mathsf{Bad}_{\mathrm{perm}}$, the leaf's $\pi$-calls are disjoint from all other
roles. Applying MRV15 Theorem 2 (FKD, Section 6.2) — including the outer-keyed initialization (ADMV15) and
overwrite-mode coverage established there — the PRF advantage for leaf $i$ is at most
$\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)$, where $l_i$ is the number of duplexing calls for leaf $i$.

**Lemma 2 (State-direction equivalence).**
For fixed $(K_{tw}, i)$ and any plaintext-ciphertext pair of equal length, `encrypt` and `decrypt` induce identical
internal states because both write ciphertext bytes into the rate. This is structural (no probabilistic component): the overwrite rule `S[pos] = ct[j]` is executed
identically in both directions. In `encrypt`, the ciphertext byte is computed as `pt[j] XOR S[pos]` and then written
back via the overwrite; in `decrypt`, the ciphertext byte is already available and written directly. Either way, the
state after the overwrite contains the same ciphertext byte at the same position, so subsequent permutation inputs -- and
therefore the tag -- are identical.

**Lemma 3 (Fixed-key bijection).**
For fixed $(K_{tw}, i)$ and message length, the encrypt function is a deterministic, invertible map on the message
space. Each ciphertext byte $\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]$ uniquely determines
$\mathit{pt}[j]$ given the state, and the state evolution (overwriting $S[\mathit{pos}]$ with $\mathit{ct}[j]$) is
identical in both directions (Lemma 2). Therefore encryption is a bijection between equal-length plaintexts and
ciphertexts. Invertibility is witnessed by the decrypt function, which reverses each byte-level XOR step given
the same state evolution (Lemma 2). Because each chunk is processed by an independent leaf with its own $(K_{tw}, i)$,
and each leaf's encrypt is individually a bijection, the full $n$-leaf encrypt function (which concatenates the
per-leaf outputs) is also a bijection between equal-length plaintexts and ciphertexts for a fixed key and chunking.
Chunking is determined solely by total message length (ceiling division by $B$), so equal-length messages always have
identical chunking.

This bijection is used in Section 6.10 (CMT-4) to rule out two different plaintexts opening the same ciphertext under
one key.

**Final-node tag (n = 1).** For single-chunk messages, the final node is a single Duplex that inits with
$(K_{tw}, 0)$ via `pad_permute(0x08)`, encrypts the entire message (overwrite mode, covered by Lemma 2), and squeezes
the tag via `pad_permute(0x07)`. This is one continuous FKD evaluation. MRV15 Theorem 2 (FKD) applies to the entire
sequence, with the outer-keyed initialization covered by ADMV15 (same argument as Section 6.2). By domain separation
(Section 6.3, set $\mathcal{T}_s$), the final node's tag-squeeze $\pi$-call is disjoint from all leaf and KDF calls.
The tag output is therefore pseudorandom with advantage at most $\varepsilon_{\mathrm{ks}}(1, \ell_f, \ell_f, t)$,
where $\ell_f$ covers all duplexing calls in the final node (init + encryption blocks + tag squeeze).

**Final-node tag (n > 1).** For multi-chunk messages, the final node is a single Duplex that:

1. Inits with $(K_{tw}, 0)$ via `pad_permute(0x08)`.
2. Encrypts chunk 0 (overwrite mode, covered by Lemma 2).
3. XOR-absorbs HOP_FRAME and chain values (standard XOR-absorb).
4. Applies `pad_permute(0x06)` and squeezes the tag.

This is one continuous FKD evaluation. The overwrite-mode equivalence (Lemma 2) covers the encryption phase; standard
XOR-absorb covers framing and chain-value absorption. MRV15 Theorem 2 (FKD) applies to the entire sequence, with the
outer-keyed initialization covered by ADMV15 (same argument as Section 6.2). By domain separation (Section 6.3, set
$\mathcal{T}_f$), the final node's tag-squeeze $\pi$-call is disjoint from all leaf and KDF calls. The tag output is
therefore pseudorandom with advantage at most $\varepsilon_{\mathrm{ks}}(1, \ell_f, \ell_f, t)$, where $\ell_f$
covers all duplexing calls in the final node (init + encryption blocks + absorption blocks + tag squeeze).

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
  return TreeWrap128.Encrypt(K, N, AD, M_b)
```

By the bridge theorem (Section 6.4), it suffices to bound
$\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}}$ -- the IND-CPA advantage of the internal functions under
independent uniformly random per-context keys.

**Claim.** Within $\mathsf{G}_1$ conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$, the IND-CPA advantage of the internal functions is
negligible: $\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} \le \sigma^2/2^{1601}$ (the PRP/PRF switching
distance, absorbed by $\varepsilon_{\mathrm{cap}}$ per the Section 6.1 convention).

*Justification.* In $\mathsf{G}_1$ conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$:

- Each encryption query uses a fresh nonce (nonce-respecting), so each context string $X$ is distinct.
- Distinct contexts map to independent uniformly random keys in $\mathsf{G}_1$.
- Under a truly random key $K_{tw}$ (from the lazy RF in $\mathsf{G}_1$) and the ideal permutation conditioned on
  $\neg\mathsf{Bad}_{\mathrm{perm}}$, the ciphertext distribution is independent of the adversary's plaintext choice.
  The argument proceeds by induction over rate blocks (using the keyed-sponge pseudorandomness from Section 6.2 and
  Lemma 1, Section 6.6), showing that each ciphertext block is uniformly distributed regardless of the plaintext:
  - *Block 0:* The `init` step absorbed the truly random key $K_{tw}$ and applied $\pi$ via `pad_permute` (one
    permutation call); the resulting state is uniformly random (see Lemma 1, Section 6.6). The first rate block of
    keystream bytes — $S[0]$ through $S[R{-}1]$ — comes directly from this post-init permutation output, so they are
    uniform. (The next $\pi$-call occurs only when `pos` reaches $R$ during encryption, producing the state for
    Block 1.) The ciphertext byte
    $\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]$ is uniform because XOR with a uniform value is uniform.
    The state is then overwritten: $S[\mathit{pos}] \leftarrow \mathit{ct}[j]$. Crucially, the overwritten state
    contains the *ciphertext* byte (which is uniform), not the plaintext byte. The adversary's plaintext choice
    determines *which* uniform value $\mathit{ct}[j]$ takes (via the XOR), but not its *distribution*.
  - *Block $j > 0$:* The overwrite rule has written $\mathit{ct}[0..j{-}1]$ (uniform by the inductive hypothesis)
    into the rate. The capacity state is carried forward from the previous permutation output. Conditioned on
    $\neg\mathsf{Bad}_{\mathrm{perm}}$, this capacity has not appeared in any other permutation call, so the full
    permutation input (rate || capacity) is fresh. The ideal permutation on a fresh input produces a uniformly random
    output. Therefore $\mathit{ct}[j]$ is again uniform, and the same overwrite argument applies.
  - By induction, all ciphertext bytes are uniform. Since only ciphertext bytes (not plaintext bytes) enter the sponge
    state via the overwrite rule, the state evolution is determined by the uniform ciphertext sequence, not by the
    adversary's plaintext choice. Two different plaintexts produce different ciphertext values but with identical
    (uniform) distributions.
  - **Final partial block.** The last block may contain $0 \le k < R$ ciphertext bytes followed by `pad_permute`. The
    $k$ ciphertext bytes are uniform by the same XOR-with-uniform-state argument as intra-block bytes above. The
    `pad_permute` call writes the domain byte and 0x80 padding into fixed rate positions and applies $\pi$. Under
    $\neg\mathsf{Bad}_{\mathrm{perm}}$, the resulting capacity state is fresh (distinct from all prior capacity
    outputs), so the squeeze output (tag or chain value) is also approximately uniform. The partial block therefore
    inherits the same uniformity guarantee as full blocks.

The adversary therefore receives approximately uniformly random ciphertexts regardless of which plaintext it submits.

The bare IND-CPA advantage is therefore zero (absorbed into $\varepsilon_{\mathrm{cap}}$ via the PRP/PRF switching
convention of Section 6.1). The total bound follows from the decomposition in Section 6.5.

### 6.8 INT-CTXT

```
Game INT-CTXT(A):
  K <-$ {0,1}^{|K|}; S <- {}
  win <- A^{Enc, Forge}
  return win

Oracle Enc(N, AD, M):
  C <- TreeWrap128.Encrypt(K, N, AD, M)
  S <- S union {(N, AD, C)}
  return C

Oracle Forge(N, AD, C):
  if (N, AD, C) in S: return bot
  return TreeWrap128.Decrypt(K, N, AD, C) != None
```

**Claim.** $\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}.$

*Justification.* In $\mathsf{G}_1$ conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$, each
forgery attempt targets a context with a uniformly random key. By the exact uniformity principle (Section 6.1), the tag-squeeze $\pi$-call has a fresh input
(distinct capacity state under $\neg\mathsf{Bad}_{\mathrm{perm}}$), so the tag is a truly uniform $\tau$-byte value. Each forgery attempt — i.e., a (ciphertext, tag) pair not previously output by the
encryption oracle (standard INT-CTXT definition) — must guess the correct $\tau$-byte tag value, succeeding with
probability at most $2^{-8\tau}$.

Even if the adversary has previously queried encryption on the same context and observed one valid tag, a different
ciphertext produces a different tag. For $n = 1$: a different ciphertext produces different rate content after
overwrite, diverging capacity states at the next permutation call (under $\neg\mathsf{Bad}_{\mathrm{perm}}$), yielding
an independent tag. For $n > 1$: a different ciphertext in at least one chunk produces a different chain value;
the final node absorbs different data, producing a different capacity state and hence a different tag.

If the forged ciphertext has a different length, the chunking or final-block `pos` differs, producing a structurally
different tag computation. If the forgery targets a different context $(N', AD')$, the derived key differs, so the tag
computation is independent (different init capacity states, no capacity collision under
$\neg\mathsf{Bad}_{\mathrm{perm}}$). Across $S$ attempts (union bound):

$$
\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le \frac{S}{2^{8\tau}}.
$$

The total bound follows from the decomposition in Section 6.5.

If tags are truncated to $T<\tau$ bytes, replace $S/2^{8\tau}$ with $S/2^{8T}$.

### 6.9 IND-CCA2 (Nonce-Respecting)

IND-CCA2 follows from IND-CPA and INT-CTXT via the generic composition theorem of Bellare and Namprempre (BN00;
extended to the nonce-based setting by Namprempre, Rogaway, and Shrimpton, NRS14).

**Step 1: Bare-level composition.** By the BN00/NRS14 composition theorem, for the internal functions under a fixed
random key:

$$
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} + \mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}}.
$$

An IND-CCA2 adversary has access to both an encryption oracle and a decryption oracle. By INT-CTXT, the decryption
oracle rejects all adversary-crafted queries (except with probability
$\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}}$), so it provides no useful information beyond what the
encryption oracle already reveals. Removing the decryption oracle reduces the game to IND-CPA.

**Step 2: Substitute bare bounds.** From Sections 6.7 and 6.8:
$\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} \le \sigma^2/2^{1601}$ (absorbed by
$\varepsilon_{\mathrm{cap}}$ per the Section 6.1 convention) and
$\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}$. Therefore:

$$
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \frac{S}{2^{8\tau}}.
$$

**Step 3: Total bound.** The total bound follows from the decomposition in Section 6.5.

> *Note on construction type.* TreeWrap128 is structurally an encrypt-and-MAC scheme (the tag is derived from the
> same sponge state as the ciphertext), not an Encrypt-then-MAC scheme with independent keys. The BN00 composition
> theorem (Theorem 3.2) is a general result: it states that *any* symmetric encryption scheme satisfying both IND-CPA
> and INT-CTXT also satisfies IND-CCA2. The theorem's only preconditions are these two properties of the composed
> scheme, not any requirement on its internal structure (e.g., independent keys or separate MAC). Sections 6.7 and 6.8
> establish IND-CPA and INT-CTXT for TreeWrap128 directly, so the theorem applies. The overwrite-mode sponge ensures
> that the tag depends on the ciphertext (ciphertext bytes are written into the rate before the tag squeeze), which is
> why INT-CTXT holds despite the shared state.

Nonce reuse for the same $(K,N,AD)$ is out of scope for this claim and breaks standard nonce-respecting
IND-CCA2 formulations.

### 6.10 CMT-4 (Fixed Master Key)

This theorem follows the standard Bellare-Hoang committing-security notion (CMT-4, see Section 9): a ciphertext should not
admit two distinct valid openings under one fixed secret key. The proof is a composition argument over Section 6.4 plus
fixed-key injectivity of the internal functions (Lemma 3).

```
Game CMT-4(A):
  K <-$ {0,1}^{|K|}
  (C*, (N, AD, M), (N', AD', M')) <- A^{Enc}
  require (N, AD, M) != (N', AD', M')
  require |M| = |M'| = |C*| - tau
  return Dec(K, N, AD, C*) = M and Dec(K, N', AD', C*) = M'

Oracle Enc(N, AD, M):
  return TreeWrap128.Encrypt(K, N, AD, M)
```

Working in $\mathsf{G}_1$ conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$ (Section 6.5):

Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$:

- **Case 1: same context** $(N,AD)=(N',AD')$. Both openings use the same derived key. Since
  $(N,AD,M) \neq (N',AD',M')$ and the contexts are equal, we must have $M \neq M'$. Because the ciphertext $C^\star$
  fixes the plaintext length ($|M| = |M'| = |C^\star|$ minus the tag), both messages have identical chunking. Then two
  different messages opening the same $C^\star$ under the same key and chunking contradict Lemma 3 (fixed-key
  bijection), so this case is impossible.
- **Case 2: different contexts** $(N,AD)\neq(N',AD')$. Distinct contexts map to independent random keys in
  $\mathsf{G}_1$. A dual valid opening requires the adversary to produce a single $C^\star$ whose embedded tag is valid
  under both derived keys simultaneously.

  **Adversary strategy.** The adversary fixes $C^\star = \mathit{ct}^\star \| T^\star$. One valid opening (say under
  context $(N,AD)$) fixes $T^\star$ to the unique correct tag for $\mathit{ct}^\star$ under that context's derived key.
  The second opening requires that $\mathrm{DecryptAndMAC}$ under the independently random key for $(N',AD')$ also
  produces tag $T^\star$ on $\mathit{ct}^\star$. By the exact uniformity principle (Section 6.1), the
  tag-squeeze $\pi$-call under the second key has a fresh input, so this second tag is truly uniform
  over $\{0,1\}^{8\tau}$ and independent of the first, so the match probability is at most $2^{-8\tau}$ per
  candidate context. Over at most $Q$ candidate contexts (encryption-oracle queries plus the two openings), the union
  bound gives $\Pr[\text{match}] \leq Q / 2^{8\tau}$.

Therefore:

$$
\mathrm{Adv}_{\mathrm{CMT\text{-}4}}^{\mathrm{bare}} \le \frac{Q}{2^{8\tau}}.
$$

The total bound follows from the decomposition in Section 6.5. For $\tau = 32$, the bare denominator is $2^{256}$.

### 6.11 Summary of Bounds

Each property's total advantage combines the bridge-hop cost (Section 6.4) with the bare advantage
(Sections 6.7–6.10):

$$
\mathrm{Adv}_{\Pi} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}} + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}.
$$

| Property | $\mathrm{Adv}^{\mathrm{bare}}$ | Total |
|----------|-------------------------------|-------|
| IND-CPA  | $0$ | $\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}} + \varepsilon_{\mathrm{ctx\text{-}coll}}$ |
| INT-CTXT | $S / 2^{8\tau}$ | $\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}} + \varepsilon_{\mathrm{ctx\text{-}coll}} + S / 2^{8\tau}$ |
| IND-CCA2 | $S / 2^{8\tau}$ | $\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}} + \varepsilon_{\mathrm{ctx\text{-}coll}} + S / 2^{8\tau}$ |
| CMT-4    | $Q / 2^{8\tau}$ | $\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}} + \varepsilon_{\mathrm{ctx\text{-}coll}} + Q / 2^{8\tau}$ |

Where $\varepsilon_{\mathrm{cap}} = (\sigma + t)^2 / 2^{c+1}$,
$\varepsilon_{\mathrm{ks}} = \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t)$
is the MRV15 PRF bound (Section 6.2), and
$\varepsilon_{\mathrm{ctx\text{-}coll}} = q_{\mathrm{ctx}}^2 / 2^{8C+1}$ is the PRF-RF switching cost.
Parameters are defined in Section 6.1.

## 7. Operational Security

### 7.1 Bare Usage (EncryptAndMAC / DecryptAndMAC)

The internal `EncryptAndMAC`/`DecryptAndMAC` functions (Section 5.1) may be used directly by callers that manage
per-invocation key uniqueness and tag verification externally. This is an advanced interface.

> [!WARNING]
> Bare usage bypasses the TreeWrap128 key derivation and tag verification. The following caller obligations are
> **mandatory** for security; failure to enforce any of them voids the security properties of Section 6.

| Property target              | Caller obligation                                                                             |
|------------------------------|-----------------------------------------------------------------------------------------------|
| IND-CPA-like confidentiality | Ensure key uniqueness per `EncryptAndMAC` invocation.                                         |
| INT-CTXT-like authenticity   | Compare tags in constant time; reject plaintext on mismatch.                                  |
| IND-CCA2-like behavior       | Do not release/act on plaintext before successful tag verification.                           |
| CMT-4                        | Ensure derived keys are independent across distinct AEAD contexts.                                |

### 7.2 Chunk Reordering, Length Changes, and Empty Input

- Reordering chunks changes leaf-index binding (`key || LEU64(index)`), so recomputed tag changes.
- Truncation/extension changes chunk count $n$, changing `length_encode(n-1)` in the chaining-hop suffix.
- Empty plaintext uses $n=1$: the final node encrypts the empty message and produces the tag via `pad_permute(0x07)`.

### 7.3 Side Channels

Implementations MUST be constant-time with respect to secret-dependent control flow and memory access.

- No lookup tables indexed by secret state bytes.
- Tag verification MUST use constant-time equality.
- Partial-block logic may branch on public length, not on secret data.

### 7.4 Operational Usage Limits (Normative)

To claim the 128-bit security target in this specification, deployments MUST enforce per-master-key usage limits (a key
epoch) and rotate to a fresh master key before exceeding them.

Implementations MUST maintain the following per-key-epoch counters:

- $q_{\mathrm{enc}}$: number of encryption invocations.
- $\sigma_{\mathrm{total}} = \sigma_{\mathrm{treewrap128}} + \sigma_{\mathrm{other\ keccak\ uses\ in\ scope}}$ (i.e., all Keccak-p evaluations sharing the same ideal-permutation instance within one key epoch).
- $q_{\mathrm{nonce}}$: number of random nonces used (only for random-nonce deployments).
- $S$: number of failed decryption/verification attempts processed (forgery attempts).

Required baseline profile (MUST):

- Enforce $\sigma_{\mathrm{total}} \le 2^{60}$.
- Define and enforce an encryption-invocation cap $q_{\mathrm{enc}} \le q_{\mathrm{enc,cap}}$ per key epoch.
- Enforce nonce uniqueness per key epoch. Deterministic nonces (counters or sequences) MUST NOT repeat within one key
  epoch; random-nonce deployments SHOULD use a large nonce space (e.g., 192 or 256 bits).
- For deterministic nonces, choose $q_{\mathrm{enc,cap}}$ so nonce values cannot wrap or repeat within the epoch.
- If random nonces are used, additionally enforce
  $q_{\mathrm{nonce}}(q_{\mathrm{nonce}}-1)/2^{b_n+1} \le p_{\mathrm{nonce}}$ for nonce bit-length $b_n$ and chosen nonce-collision target
  $p_{\mathrm{nonce}}$.
- Define and enforce a failed-verification budget $S_{\mathrm{cap}}$ per key epoch (RECOMMENDED: $S_{\mathrm{cap}} = 2^{32}$).
  If $S > S_{\mathrm{cap}}$, implementations MUST stop accepting further decryption attempts for that epoch and rotate to
  a fresh key epoch before resuming.
- On any cap exceedance (workload, invocation, nonce, or failed-verification policy), implementations MUST rotate to a
  fresh key epoch before any further encryption.

Analysis interpretation (normative for this profile): evaluate the Section 6 bounds using default offline-work profile
$t = 2^{64}$.

Expert profile (non-normative): deployments with stronger review/monitoring may choose workload caps above $2^{60}$, up
to $2^{64}$, using the same counter model.

Security interpretation remains the Section 6 bound family evaluated at observed counters, with adversary offline budget
parameter $t$ treated as an analysis parameter (not an operationally measurable quantity).

**Multi-user security.** For deployments spanning $U$ independent master keys, the total advantage is at most $U$ times
the per-key bound (union bound). The offline budget $t$ and the $\mathsf{Bad}_{\mathrm{perm}}$ event are global (shared
across all keys under the same ideal permutation), so $\varepsilon_{\mathrm{cap}}$ must be evaluated with the global
online query count $\sigma = \sum_u \sigma_u$ across all $U$ keys. Concretely, a deployment with $U$ keys achieves at
most $U \cdot \varepsilon$ total advantage, where $\varepsilon$ is the single-key bound with $\sigma$ set to the global
total and per-key workload counters for the remaining terms.

Non-normative sensitivity profiles for reviewers:

| Profile  | Offline-work parameter | Typical audience                      |
|----------|------------------------|---------------------------------------|
| Baseline | $t = 2^{64}$           | default deployment conformance        |
| Audit    | $t = 2^{60}$           | realistic adversary budget; confirms margin at lower workloads |
| Extended | $t = 2^{72}$           | research-oriented stress analysis     |

Profile choice changes only analytical interpretation of bounds; it does not change algorithm behavior, implementation
requirements, or interoperability.

Appendix C remains non-normative operational guidance for instrumentation and budgeting workflows.

### 7.5 Implementation Design Callouts (Non-Normative)

TreeWrap128's tree topology exists to exploit data-level parallelism: independent leaf chunks can be encrypted or
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
- **Keep domain bytes and index mapping exact.** The constants `0x08`, `0x0B`, `0x09`, `0x07`, `0x06` and the
  `key ‖ LEU64(index)` binding (index 0 for the final node, 1 through $n$ for leaves) are structural for
  interoperability and security analysis.
- **No misuse resistance (MRAE).** TreeWrap128 is not SIV-style: nonce reuse leaks plaintext XOR (Section 6.7).
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

Each row is one SIMD register wide (32 bytes for 4×64-bit on AVX2, 64 bytes for 8×64-bit on AVX-512). This layout has
two critical properties:

1. **Absorb is a single vector XOR per lane.** To absorb a rate block across all N instances, load the corresponding
   plaintext bytes from N input streams into a vector and `VPXOR` it into the lane — one instruction for N states.
2. **Permutation rounds operate on all N states simultaneously.** Every θ/ρ/π/χ/ι step is the same vector operation
   applied to 25 registers, processing N permutations for the cost of one.

The N input streams are typically laid out at a fixed stride (the chunk size, 8192 bytes), so absorbing lane `i` across
all instances is a gather from `input + instance × stride + i × 8`. On platforms where explicit gather is expensive
(AVX2 `VPGATHERQQ` at width 4 is slower than discrete loads), loading each instance's lane individually and packing
into a vector with insert or shuffle instructions is faster.

**Cascade scheduling.** Given a batch of complete chunks, process them widest-first using the largest available kernel,
then fall back to narrower kernels for the remainder. For example, 11 chunks would be scheduled as one x8 batch
followed by one x2 batch and one x1. Each batch initializes an N-way PlSnP state by absorbing
`key ‖ LEU64(leaf_index)` into each instance, runs the fused absorb-permute loop over the chunk data, then extracts N
chain values. Chain values are absorbed into the final node incrementally — there is no need to buffer them all before
finalizing.

The maximum useful kernel width is platform-dependent:

| Platform | Native ceiling | x8 strategy |
|----------|---------------|-------------|
| amd64 + AVX-512 | x8 (ZMM, state-resident in Z0–Z24) | Native |
| amd64 + AVX2 | x4 (YMM) | 2 × x4 cascade |
| arm64 + NEON | x2 (ASIMD 2×uint64) | 4 × x2 cascade |
| Scalar fallback | x1 | Serial |

An x8 kernel implemented as two sequential x4 invocations still outperforms four sequential x2 invocations because the
PlSnP state stays hot in registers across the two halves.

**Fused absorb-permute loops.** The inner loop of each leaf processes a full rate block (168 bytes = 21 lanes) per
iteration. A fused implementation absorbs the block and immediately permutes without storing and reloading the PlSnP
state between iterations. This eliminates 25×N loads and 25×N stores per block that a non-fused design would require to
move the PlSnP state between separate absorb and permute functions. At x8 width on AVX-512, where the state occupies
all 25 ZMM registers, the savings are substantial.

**Preserve empty and single-chunk fast paths.** Empty inputs and single-chunk messages (≤ 8192 bytes) never enter the
tree — they are processed entirely through the final node's duplex. Keep these paths free of tree-scheduling overhead,
as they dominate latency-sensitive workloads.

## 8. Comparison with Traditional AEAD

TreeWrap128 differs from traditional AEAD in several respects.

**Nonce-free internal primitive.** The internal encrypt-and-MAC functions take only a key and data. Nonces are consumed
by the TurboSHAKE128-based KDF to derive a unique internal key, not passed to the encrypt/MAC layer itself.

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs -- they prove authenticity but are not
necessarily pseudorandom. TreeWrap128's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (Section 6.1). This stronger property is useful for protocols that derive further keying material from the tag.

### 8.1 Operational Safety Limits

Operational planning assumptions used in this section: $p = 2^{-50}$, 1500-byte messages, TreeWrap128 cost
$\approx 11$ Keccak-p calls/message (1 KDF + 10 leaf calls), $\ell \approx 49$ max input blocks per keyed-sponge
evaluation, and per-key accounting (single key / key epoch). Figures are conditional on the Section 6 model assumptions
for Keccak-p[1600,12] and the selected offline-work profile.

Under the MRV15 keyed-sponge PRF framework (Section 6.2), the dominant online-online term across the construction is
the KDF's FKS capacity term $2q^2\ell / 2^c$ (Theorem 1). Per-leaf FKD capacity terms (Theorem 2) are negligible since
each leaf has $q = 1$. For a conservative estimate, set $q$ to the number of TreeWrap128 encryptions and $\ell = 49$
(worst-case blocks absorbed per message, which overstates the per-evaluation input length and is therefore safe). With $c = 256$ and target
$p = 2^{-50}$: $q^2 \le 2^{256-50} / (2 \cdot 49) \approx 2^{199}$, so $q \lesssim 2^{99.5}$ messages. At 1500
bytes/message the proof-bound volume is approximately $2^{80}$ GiB per key epoch. This is an analytical upper bound,
not the practical deployment limit when random nonces are used.

For deployment planning, use:

$$
\text{practical per-key volume} = \min(\text{proof-bound volume},\ \text{nonce-collision-limited volume}).
$$

With uniformly random 128-bit nonces and collision target $p = 2^{-50}$, the nonce budget is approximately
$q_{\mathrm{nonce}} \lesssim 2^{39.5}$ encryptions per key (birthday approximation), so at 1500 bytes/message:

$$
\text{nonce-collision-limited volume} \approx 2^{39.5} \cdot 1500\ \text{bytes} \approx 2^{20.1}\ \text{GiB}.
$$

TreeWrap128 supports longer nonces (e.g., 192 or 256 bits) with the same construction; this increases the random-nonce
collision budget in the usual birthday way.

Example planning table (collision target $p = 2^{-50}$, record size = 1500 bytes):

| Nonce size | Record size | Limiting factor  | Approx safe volume per key epoch |
|------------|-------------|------------------|----------------------------------|
| 128-bit    | 1500 B      | nonce collisions | $\approx 2^{20.1}$ GiB           |
| 192-bit    | 1500 B      | nonce collisions | $\approx 2^{52.1}$ GiB           |
| 256-bit    | 1500 B      | proof bound      | $\approx 2^{80}$ GiB             |

For a different record size, scale the nonce-collision-limited rows linearly with bytes/record and then apply the same
minimum rule against the proof-bound volume.

Configured usage limits SHOULD be driven by nonce policy and key-epoch rotation controls (Section 7.4), not by the asymptotic
proof-bound figure alone.

## 9. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007. Establishes
  the flat sponge claim (a heuristic generic security bound for random sponges based on inner-collision analysis). Referenced
  in the non-normative note in Section 6.2.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint
  2013/231. Defines the tree hash coding framework used by KangarooTwelve and TreeWrap128.
- RFC 9861: KangarooTwelve and TurboSHAKE.
- Bertoni, G., Daemen, J., Hoffert, S., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B. "TurboSHAKE." IACR ePrint 2023/342.
  Primary specification and design rationale for TurboSHAKE.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B. "KangarooTwelve: fast hashing based on
  Keccak-p." IACR ePrint 2016/770. Security and design context for the Sakura-based tree structure.
- Keccak Team. "Third-party cryptanalysis." https://keccak.team/third_party.html. Curated summary table of published
  cryptanalysis results and round counts across Keccak-family modes and raw permutations.
- Maurer, U., Renner, R., and Holenstein, C. "Indifferentiability, Impossibility Results on Reductions, and
  Applications to the Random Oracle Methodology." TCC 2004. Introduces indifferentiability and the core composition
  theorem framework used for random-oracle replacement arguments.
- Coron, J.-S., Dodis, Y., Malinaud, C., and Puniya, P. "Merkle-Damgård Revisited: How to Construct a Hash Function."
  CRYPTO 2005. Applies the MRH indifferentiability composition theorem to hash function constructions; referenced in the
  non-normative note in Section 6.4.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." EUROCRYPT 2022. Defines the CMT-4 committing
  security notion.
- Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the Generic
  Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2; used in Section 6.9.
- Namprempre, C., Rogaway, P., and Shrimpton, T. "Reconsidering Generic Composition." EUROCRYPT 2014. Extends the
  BN00 composition theorem to the nonce-based setting; used in Section 6.9.
- Ristenpart, T., Shacham, H., and Shrimpton, T. "Careful with Composition: Limitations of the Indifferentiability
  Framework." Eurocrypt 2011 (ePrint 2011/339 as "Careful with Composition: Limitations of Indifferentiability and Universal Composability").
  Highlights multi-stage composition caveats; motivates explicit game-hop arguments in composed proofs.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass Authenticated Encryption
  and Other Applications." SAC 2011. IACR ePrint 2011/499. Establishes the duplex-sponge equivalence (Lemma 3: each
  duplex output equals a sponge evaluation on concatenated padded inputs), proves SpongeWrap AEAD security bounds
  (Theorem 1), and gives overwrite-mode security (BDPVA11 §6.2, Algorithm 5, Theorem 2: Overwrite is as secure as
  Sponge); establishes that all intermediate rate outputs -- not just terminal squeezes -- are covered by the duplex
  security bound.
- Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex: Applications to
  Authenticated Encryption." Asiacrypt 2015. IACR ePrint 2015/541. Primary security framework for TreeWrap128. Proves
  beyond-birthday-bound PRF security for the full-state keyed sponge (Theorem 1, FKS) and full-state keyed duplex
  (Theorem 2, FKD) in the ideal-permutation model. Theorem 2 (FKD) is used for leaf ciphers; Theorem 1 (FKS) is used
  for the KDF sponge. Used throughout Section 6.
- Andreeva, E., Daemen, J., Mennink, B., and Van Assche, G. "Security of Keyed Sponge Constructions Using a Modular
  Proof Approach." FSE 2015. Proves PRF security of both inner-keyed and outer-keyed sponge variants. The outer-keyed
  result covers TreeWrap128's rate-absorbed key initialization (Section 6.2).
- Dinur, I., Dunkelman, O., and Shamir, A. "New attacks on Keccak-224 and Keccak-256." FSE 2012; published as
  "Improved practical attacks on round-reduced Keccak" in Journal of Cryptology 27(4), 2014. Reports practical 4-round
  collisions and 5-round near-collision results in standard Keccak-224/256 settings.
- Keccak Team. "Keccak Crunchy Crypto Collision and Pre-image Contest."
  https://keccak.team/crunchy_contest.html. Public contest record for reduced-round Keccak[c=160] instances, including
  6-round collision solutions.
- Duc, A., Guo, J., Peyrin, T., and Wei, L. "Unaligned Rebound Attack - Application to Keccak." IACR ePrint 2011/420.
  Gives differential distinguishers up to 8 rounds of Keccak internal permutations.
- Aumasson, J.-P. and Meier, W. "Zero-sum distinguishers for reduced Keccak-f and for the core functions of Luffa and
  Hamsi." 2009. https://www.aumasson.jp/data/papers/AM09.pdf. Presents zero-sum distinguishers up to 16 rounds.

## 10. Test Vectors

### 10.1 Internal Function Vectors

All internal function vectors use:

- **Key:** 32 bytes `00 01 02 ... 1f`
- **Plaintext:** `len` bytes `00 01 02 ... (len-1) mod 256`

Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.

#### 10.1.1 Empty Plaintext (MAC-only, n = 1)

| Field | Value |
|-------|-------|
| len | 0 |
| ct | (empty) |
| tag | `4a06dd2e8c2280eb2a4cb54ff4bbcd16e26809d6e1d10ae9b03ddd81dba1f70c` |

#### 10.1.2 One-Byte Plaintext (n = 1)

| Field | Value |
|-------|-------|
| len | 1 |
| ct | `b9` |
| tag | `636744e19511873009bbee34794c6d013b71834fc3ed46e0c758c8bc1655164d` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`3ec75c7e58e68df6fa8b50e538fd365e8fde86ee533b569dbec6fa259d3f8546`.

#### 10.1.3 B-Byte Plaintext (exactly one chunk, n = 1)

| Field | Value |
|-------|-------|
| len | 8192 |
| ct[:32] | `b94305614cdb24d7f83c521bf1b137e5c018aa198896607f526299d7d35c1707` |
| tag | `fc2ea76078fe107a4c0a29a1bcb7670ba59ff8477a93388c12405c0f45e6ee23` |

Flipping bit 0 of `ct[0]` yields tag
`4a781a4ec6ada1db7bea9e4968f5634073e18df476f52d0c62ee9e0aa816d142`.

#### 10.1.4 B+1-Byte Plaintext (two chunks, minimal second, n = 2)

| Field | Value |
|-------|-------|
| len | 8193 |
| ct[:32] | `b94305614cdb24d7f83c521bf1b137e5c018aa198896607f526299d7d35c1707` |
| tag | `0e14c22b6f47418cde0bf107f875f9e19fe73c533d6871c5f89fb9fda1dfa852` |

Flipping bit 0 of `ct[0]` yields tag
`b0702f781638349e5cc1fd81b60b1b2ae813b8bfba7ddfddbe330659d3ae1c96`.

#### 10.1.5 4B-Byte Plaintext (four full chunks, n = 4)

| Field | Value |
|-------|-------|
| len | 32768 |
| ct[:32] | `b94305614cdb24d7f83c521bf1b137e5c018aa198896607f526299d7d35c1707` |
| tag | `b1034d073f7106ec836388823827a050bbbe2cfbccb29a79d704b4d37a0fbc75` |

Flipping bit 0 of `ct[0]` yields tag
`684dbca2392dc17928b19943a368d630075d56fb754c15457d85d413abbca22a`.

Swapping chunks 1 and 2 (bytes 0–8,191 and 8,192–16,383) yields tag
`39032e2280f25c78fe72143f9c94bc5f8694834b8d8528aae0e07d035a8aba7c`.

#### 10.1.6 Round-Trip Consistency

For all internal function vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as
`EncryptAndMAC`.

### 10.2 TreeWrap128 Vectors

These vectors validate `treewrap128_encrypt` / `treewrap128_decrypt`, including SP 800-185
`encode_string` key derivation.

#### 10.2.1 Empty Message

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | (empty) |
| M len | 0 |
| ct‖tag | `1b581c73ae9475f3fe9a3695cbcb97d5fa6bf4fe50d5077c05307ee93333f585` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.2 33-Byte Message With 5-Byte AD

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `a0 a1 a2 ... ab` |
| AD | 10 11 12 ... 14 |
| M len | 33 (`00 01 02 ... mod 256`) |
| ct‖tag | `ad06981fb8996d3a370fdff698dde70799641537c999562e9da3cc315998790f90079f24283c57e81120e7d5c3cc5c122b32c96b41769a24c1b4bffbff76f7b92d` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.3 Multi-Chunk Message (8193 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `42 43 44 ... 61` |
| N | 12 bytes `c0 c1 c2 ... cb` |
| AD | 00 01 02 ... 10 |
| M len | 8193 (`00 01 02 ... mod 256`) |
| ct[:32] | `c865e59fbaee05479be69b2e5d321fb917c03358e7ea3ab4f5a83157ebfc0ace` |
| tag | `be9035c011815da2706dc38f548a019165ebec1987c574913e4e4f18255c7b7f` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.4 Nonce Reuse Behavior (Equal-Length Messages)

| Field | Value |
|-------|-------|
| K | 32 bytes `00 11 22 ... ff` |
| N | 12 bytes `ff ee dd cc bb aa 99 88 77 66 55 44` |
| AD | a1 a2 a3 ... a4 |
| M len | 64 (`00 01 02 ... mod 256`) |
| ct‖tag | `5105314ef74b22ad003d53ee853ad28d8eeaf3cc0e20244911d96597cf4bb37ca74cffa7ea574705198f81c0e80c3766aea6e0ef2ba1dfc92009606ac220af91b5e9fdad578dd16ab44e58fd5e8f7e58ea586dbd7a7382fe09d715e7c22eb14e` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Reusing the same `(K, N, AD)` with a different message is deterministic and yields
`ct1 xor ct2 = m1 xor m2` within each rate block (168 bytes); overwrite mode causes
keystream divergence at subsequent block boundaries (validated by this vector).
Nonce reuse is out of scope for Section 6 nonce-respecting claims.

#### 10.2.5 Swapped Nonce and AD Domains

| Field | Value |
|-------|-------|
| K | 32 bytes `0f 0e 0d ... 00` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | 10 11 12 ... 1b |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `d6c8e417669baeb1b6acb530dfef004efe1c7422c7e09821d03e9bf7e44a6d9808fb2d2c8c3466de4dc973c7c70a7692650495153855f4627b136e9da82ab591bc9762113b9b3a66f5fd507168950081` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Swapping `N` and `AD` (same byte length) yields a different `ct‖tag` and does not
validate the original `ct‖tag`.

#### 10.2.6 Empty AD vs One-Byte AD 00

| Field | Value |
|-------|-------|
| K | 32 bytes `88 99 aa ... ff` |
| N | 12 bytes `0c 0d 0e ... 17` |
| AD | (empty) |
| M len | 32 (`00 01 02 ... 1f`) |
| ct‖tag | `6c6842b44331dca922bce7f3073f51b350a00676b4dba240d32f04ab8df28b20a6b4e5dfe5917f4ea5d55f469ea5f9c796658dd1015025fb2e73f3d02936506a` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Empty AD and one-byte AD `00` are distinct contexts and produce different `ct‖tag`.

#### 10.2.7 Long AD (128 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 21 32 ... ff` |
| N | 12 bytes `ab ab ac ad ae af b0 b1 b2 b3 b4 b5` |
| AD | ab ab ab ... ab |
| M len | 17 (`00 01 02 ... 10`) |
| ct‖tag | `2a590aaa049945f3306c6a4fce20538e1c2100b200d4f6009400efb3b5495a5fe9f7decb3aa27c597db789e8f280405604` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.8 Rate-Minus-One Message (167 Bytes, R-1 Boundary)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 12 bytes `d0 d1 d2 ... db` |
| AD | 20 21 22 |
| M len | 167 (`00 01 02 ... mod 256`) |
| ct[:32] | `35eb85e8659508b92d2f7ad3714991cc40510a454493a98e471c3344ddd20c84` |
| tag | `32a0a6438ebd3b9bdcc76da34f9bc63fd2196b133cf6a3bef683b4b8c28dd43f` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.9 Exact-Rate Message (168 Bytes, R Boundary)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 12 bytes `d0 d1 d2 ... db` |
| AD | 20 21 22 |
| M len | 168 (`00 01 02 ... mod 256`) |
| ct[:32] | `35eb85e8659508b92d2f7ad3714991cc40510a454493a98e471c3344ddd20c84` |
| tag | `54d3ebf2d79bacb8ca1217643a4bb71dc90bd5b5241b78f3a2e2491133047099` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.10 Large Nonce (32 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 11 12 ... 2f` |
| N | 32 bytes `e0 e1 e2 ... ff` |
| AD | 20 21 22 |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `77431d80e360764438411dca0d9d76598d097b9fbfecb7e4e805532c5f4fff46bb3834e3df28209cb07413f531d104ed6b0d2f132c775cfd6a556b1f75f4769555751936ccab6d1a0f5cddfd3f608f0f` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

## Appendix A. Exact Per-Query $\sigma$ Formula

For a single `TreeWrap128` query on a message of length $L$ bytes with
$n = \max(1, \lceil L / B \rceil)$ chunks of sizes $\ell_0, \ldots, \ell_{n-1}$, the per-query contribution to
$\sigma$ is:

$$\sigma_{\mathrm{query}} = \underbrace{\left(\left\lfloor \frac{|\mathit{kdf\_input}|}{R} \right\rfloor + 1\right)}_{\text{KDF}} + \underbrace{\left(1 + \left\lfloor \frac{\ell_0}{R} \right\rfloor + d_f\right)}_{\text{final node}} + \underbrace{\sum_{i=1}^{n-1}\left(2 + \left\lfloor \frac{\ell_i}{R} \right\rfloor\right)}_{\text{leaves}}$$

where $d_f$ is the number of permutation calls during the final node's tag phase (1 for the tag `pad_permute`, plus
any additional calls from absorbing HOP_FRAME, chain values, and the chaining-hop suffix when $n > 1$).

More precisely:

- **KDF term.** $|\mathit{kdf\_input}|$ is the byte length of
  `encode_string(K) || encode_string(N) || encode_string(AD)`.
  Each `encode_string` contributes `left_encode(8|x|)` (2-3 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $|\mathit{kdf\_input}| = (3+32) + (2+12) + (2+0) = 51$ bytes, giving
  $\lfloor 51 / 168 \rfloor + 1 = 1$ Keccak-p call.
  (The `+1` accounts for TurboSHAKE's pad+permute step even when the absorb phase ends exactly on a rate boundary.)
- **Final node term.** The final node (index 0) costs $1$ (init `pad_permute`) $+$
  $\lfloor \ell_0 / R \rfloor$ (unpadded intermediate permutations during chunk-0 encryption) $+$ $d_f$ (tag phase).
  For $n = 1$: $d_f = 1$ (one `pad_permute(0x07)`). For $n > 1$: $d_f$ accounts for absorbing the 8-byte HOP_FRAME,
  $(n-1)$ chain values of $C$ bytes each, the chaining-hop suffix ($|\mathrm{length\_encode}(n-1)| + 2$ bytes), and the
  final `pad_permute(0x06)`. These are XOR-absorbed contiguously into the rate starting from the position left after
  chunk-0 encryption.
- **Leaf term.** Each leaf (indices $1, \ldots, n-1$) costs $2$ (init `pad_permute` + terminal `pad_permute` for
  `chain_value`) $+$ $\lfloor \ell_i / R \rfloor$ (unpadded intermediate permutations on full-rate blocks). For a
  full $B = 8192$-byte chunk: $2 + \lfloor 8192 / 168 \rfloor = 2 + 48 = 50$. The leaf sum is empty when $n = 1$.

## Appendix B. Reference Implementation of Keccak-p[1600,12] and TurboSHAKE128

This appendix provides a reference Python implementation of the cryptographic primitives used by TreeWrap128. It
is intended for specification clarity and test-vector generation; production implementations should use
platform-optimized Keccak libraries.

### Keccak-p[1600,12]

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

### TurboSHAKE128

```python
def turboshake128(msg: bytes, domain_byte: int, output_len: int) -> bytes:
    """TurboSHAKE128(M, D, ell) as specified in RFC 9861."""
    S = bytearray(200)
    # Absorb.
    pos = 0
    for i in range(0, len(msg), R):
        block = msg[i : i + R]
        for j, b in enumerate(block):
            S[pos + j] ^= b
        pos += len(block)
        if pos == R:
            keccak_p1600(S)
            pos = 0
    # Pad and switch to squeezing.
    S[pos] ^= domain_byte
    S[R - 1] ^= 0x80
    keccak_p1600(S)
    # Squeeze.
    out, pos = bytearray(), 0
    while len(out) < output_len:
        if pos == R:
            keccak_p1600(S)
            pos = 0
        n = min(R - pos, output_len - len(out))
        out.extend(S[pos : pos + n])
        pos += n
    return bytes(out)
```

### Integer and String Encodings

`left_encode` and `encode_string` follow NIST SP 800-185. `length_encode` follows RFC 9861: for $x = 0$ it returns a
single `0x00` byte rather than `0x00 0x01`. TreeWrap128 only calls `length_encode` with $n \geq 2$, so the difference is
unreachable in practice.

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

def encode_string(x: bytes) -> bytes:
    """SP 800-185: left_encode(len(x) * 8) || x."""
    return left_encode(len(x) * 8) + x
```

## Appendix C. Deployment Budgeting Across TreeWrap128, TurboSHAKE, and KangarooTwelve (Non-Normative)

This appendix is operational guidance for practitioners combining multiple Keccak-based components in one system.
It is not part of the normative algorithm definition.

### C.1 Why this matters

The security bounds in Section 6 include a capacity birthday bound term:

$$
\varepsilon_{\mathrm{cap}} = \frac{(\sigma + t)^2}{2^{c+1}}.
$$

This is the simplest conservative estimate for combined online ($\sigma$) and offline ($t$) Keccak-p call budgets.
For tighter per-key planning under the MRV15 keyed-sponge framework, use $\varepsilon_{\mathrm{ks}}$ from Section 6.2,
which provides beyond-birthday-bound security for the keyed setting.

When a deployment uses multiple Keccak-based components under related security assumptions, a conservative practice is
to budget their Keccak-p calls together rather than treating each component in isolation.

### C.2 Practitioner workflow

For a chosen operational window (for example, per key epoch, per process lifetime, or per day), define:

```text
sigma_total = sigma_treewrap128 + sigma_turboshake + sigma_k12 + sigma_other_keccak
```

where each term is the count of online Keccak-p[1600,12] calls made by that component in the window.
This is the same $\sigma_{\mathrm{total}}$ counter model used normatively in Section 7.4.

Then evaluate:

$$
\varepsilon_{\mathrm{cap}} = \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}}
$$

for your selected adversary offline budget $t$.

Use this as a planning control:

- if $\varepsilon_{\mathrm{cap}}$ is below your target risk threshold, the window budget is acceptable;
- if not, shorten the window (rotate keys/state sooner), reduce throughput per key, or separate workloads across keys.

### C.3 What implementers should instrument

At minimum, log per-window counters for:

- TreeWrap128 calls and message sizes (convert via Appendix A's per-query formula),
- TurboSHAKE/KangarooTwelve calls and absorbed lengths,
- key/epoch identifiers to support budget resets at rotation boundaries.

This enables straightforward capacity planning and post-incident verification of whether configured limits were
exceeded.

### C.4 Practical default

For most deployments, this budget is generous. The value of tracking it is not that limits are usually tight, but that:

- the system has an explicit, reviewable safety margin,
- key-rotation policy is tied to measurable cryptographic workload,
- mixed-component deployments avoid silent overuse assumptions.
