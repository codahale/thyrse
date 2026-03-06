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
enables SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf encrypts by XORing plaintext with the Keccak
sponge state and writing the ciphertext back into the rate, and leaf chain values are accumulated into a single MAC tag
via a keyed TurboSHAKE128 final node.

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

## 4. Leaf Cipher

A leaf cipher operates on a standard Keccak sponge with the same permutation and rate/capacity parameters as
TurboSHAKE128. It uses five domain separation bytes, reserved for TreeWrap128:

| Byte   | Usage                        | Procedure(s)                     | Sakura | Role |
|--------|------------------------------|----------------------------------|--------|------|
| `0x33` | Init (key/index absorption)  | `init`                           | inner  | 01   |
| `0x2B` | Final block (chain value)    | `chain_value`                    | inner  | 10   |
| `0x3B` | AEAD key derivation          | `TreeWrap128`                    | inner  | 11   |
| `0x27` | Single-node tag squeeze      | `single_node_tag`                | final  | 00   |
| `0x37` | Tag accumulation             | `EncryptAndMAC`, `DecryptAndMAC` | final  | 01   |

> [!NOTE]
> **Operational budgeting guidance.** For deployment-level guidance on budgeting Keccak-p calls across multiple
> components (TreeWrap128, TurboSHAKE128, KangarooTwelve), see Appendix C (non-normative).

Unlike the XOR-absorb approach used by SpongeWrap, the `encrypt` and `decrypt` operations write ciphertext directly
into the rate rather than XORing plaintext into it. This is the Overwrite-mode style analyzed in Bertoni et al.
(Section 6.2, Algorithm 5; Theorem 2) and used in Section 6. Intermediate (non-final) encrypt/decrypt blocks fill the
full R = 168 byte rate and permute without padding; only terminal operations (`init`, `single_node_tag`,
`chain_value`) apply TurboSHAKE-style padding via `pad_permute`. For full-rate blocks, a write-only state update is
also faster than read-XOR-write on most architectures.

> **Rate distinction.** The `init` operation absorbs at effective rate R-1 = 167 bytes: padding (domain byte at `pos`,
> `0x80` at position R-1) requires one byte reserved for the domain/padding frame, so `pad_permute` triggers when `pos`
> reaches R-1. Intermediate encrypt/decrypt blocks use the full R = 168 byte rate with no padding overhead, permuting
> via raw `keccak_p1600` when `pos` reaches R. Terminal operations (`single_node_tag`, `chain_value`) call
> `pad_permute` at whatever `pos` the final partial block leaves, accommodating both full and partial final blocks.

The leaf cipher is defined by the following reference implementation. `keccak_p1600` and `turboshake128` are defined in
Appendix B.

```python
R = 168   # Sponge rate (bytes).
C = 32    # Capacity (bytes); key and chain value size.
TAU = 32  # Tag size (bytes).
B = 8192  # Chunk size (bytes).

class LeafCipher:
    def __init__(self):
        self.S = bytearray(200)
        self.pos = 0

    def pad_permute(self, domain_byte: int):
        self.S[self.pos] ^= domain_byte
        self.S[R - 1] ^= 0x80
        keccak_p1600(self.S)
        self.pos = 0

    def init(self, key: bytes, index: int):
        for b in key + index.to_bytes(8, "little"):
            self.S[self.pos] ^= b
            self.pos += 1
            if self.pos == R - 1:
                self.pad_permute(0x33)
        self.pad_permute(0x33)

    def encrypt(self, plaintext: bytes) -> bytes:
        ct = bytearray()
        for p in plaintext:
            ct.append(p ^ self.S[self.pos])
            self.S[self.pos] = ct[-1]
            self.pos += 1
            if self.pos == R:
                keccak_p1600(self.S)
                self.pos = 0
        return bytes(ct)

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = bytearray()
        for c in ciphertext:
            pt.append(c ^ self.S[self.pos])
            self.S[self.pos] = c
            self.pos += 1
            if self.pos == R:
                keccak_p1600(self.S)
                self.pos = 0
        return bytes(pt)

    def single_node_tag(self) -> bytes:
        self.pad_permute(0x27)
        return bytes(self.S[:TAU])

    def chain_value(self) -> bytes:
        self.pad_permute(0x2B)
        return bytes(self.S[:C])
```

> [!NOTE]
> `pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at $R-1$). `init` uses domain byte
> `0x33`; `chain_value` uses `0x2B`; `single_node_tag` uses `0x27`. Intermediate encrypt/decrypt blocks use the full
> $R = 168$ byte rate and permute without padding (`keccak_p1600` directly), matching standard unpadded sponge absorb
> for non-final blocks. Both `encrypt` and `decrypt` overwrite the rate with ciphertext, so state evolution is
> identical regardless of direction. `single_node_tag` and `chain_value` begin with `pad_permute` to mix all data
> before squeezing; both outputs fit in a single squeeze block since $\max(\tau, C) = 32 \ll R = 168$.

## 5. TreeWrap128

### Notation

- `||`: Byte string concatenation.
- `LEU64(i)`: The 8-byte little-endian encoding of integer `i`.

The encodings used here (`left_encode`, `encode_string`, `length_encode`) are defined as Python functions in Appendix B.
`left_encode` and `encode_string` follow NIST SP 800-185; `length_encode` follows RFC 9861.

### Tree Topology

TreeWrap128 uses the Sakura final-node-growing topology (ePrint 2013/231, Section 5.1) without kangaroo hopping. This
differs from KangarooTwelve, which uses the same Sakura topology but with kangaroo hopping: the first chunk's data is
absorbed directly into the final node, and only subsequent chunks produce chain values.

Leaves are indexed 1 through $n$ (not 0 through $n-1$); index 0 is reserved for the final node. For $n = 1$, the single
leaf uses index 1 and produces the tag directly via `single_node_tag()` (no final node). For $n > 1$, every chunk is
processed by an independent leaf cipher that produces a C-byte chain value. A keyed final node absorbs all chain values
and produces the tag via a **keyed** TurboSHAKE128 call. The final-node input prepends the key and index 0 to the
Sakura chaining hop (Figure 4):

$$
\underbrace{\mathit{key} \;\|\; \mathrm{LEU64}(0)}_{\text{final-node keying}} \;\|\; \underbrace{\mathit{cv}_1 \;\|\; \cdots \;\|\; \mathit{cv}_{n}}_{\text{chain values}} \;\|\; \underbrace{\mathrm{length\_encode}(n)}_{\text{coded nrCVs}} \;\|\; \underbrace{\mathtt{0xFF} \;\|\; \mathtt{0xFF}}_{\text{interleaving block size}}
$$

where:

- **`key`** (C = 32 bytes): the per-invocation key $K_{tw}$, making the final node a keyed sponge.
- **`LEU64(0)`** (8 bytes): the final-node index, distinct from all leaf indices (1..$n$).
- **`cv_i`** (C = 32 bytes each): the chain value squeezed from leaf $i$ (for $i = 1, \ldots, n$).
- **`length_encode(n)`**: the Sakura coded nrCVs field, encoded per RFC 9861.
- **`0xFF || 0xFF`**: the Sakura interleaving block size encoding $I = \infty$ (no block interleaving); mantissa and
  exponent both `0xFF`.

The Sakura grammar derivation is: `final node` = `node '1'` = `chaining hop '1'` =
`nrCVs CV coded_nrCVs interleaving_block_size '0' '1'`. The trailing frame bits -- chaining hop `'0'` and
final node `'1'` -- are encoded in the TurboSHAKE128 domain byte following the Sakura suffix-extension pattern used by
KangarooTwelve. Each domain byte has the structure `11 || S || R₁R₀ || 1` (6-bit suffix, LSB-first in byte), where bit 2
is the Sakura frame bit (`S = 1` for final node, `S = 0` for inner/leaf). Final-node separability (Sakura Lemma 4) follows
directly: the tag-accumulation domain byte `0x37` has `S = 1`, while all leaf cipher domain bytes (`0x33`, `0x2B`) and
the KDF domain byte (`0x3B`) have `S = 0`.

The `0xFF || 0xFF` suffix is defined as `SAKURA_SUFFIX` in the reference code (Section 5.1).

**Domain separation.** The key prefix makes the final node a keyed sponge: its TurboSHAKE128 input begins with
`key || LEU64(0)`, XOR-absorbed into the rate before any chain values. Leaves absorb `key || LEU64(i)` for $i \geq 1$
via the LeafCipher `init` method (domain byte `0x33`). The final node's first 40 absorbed bytes therefore differ from
every leaf's (index 0 vs. index $\geq 1$), and domain byte `0x37` is distinct from leaf domain bytes (`0x33`, `0x2B`),
providing an additional layer of separation.

**Encoding injectivity.** The `key(32) || LEU64(0)(8)` prefix is fixed-length (40 bytes), so injectivity of the
remaining encoding is preserved. The suffix `length_encode(n) || 0xFF || 0xFF` is self-delimiting: `0xFF` cannot be a
valid `length_encode` byte-count (chain-value counts fit in at most 8 bytes), so the interleaving block size bytes are
unambiguously terminal, and the byte immediately preceding them gives the byte-count of $n$. Given $n$, the chain values
are parsed as $n$ consecutive $C$-byte blocks starting at offset 40.

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
# Sakura interleaving block size for I = infinity (Section 5, Tree Topology).
SAKURA_SUFFIX = b"\xff\xff"

def _tree_process(key: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for EncryptAndMAC / DecryptAndMAC."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    if n == 1:
        L = LeafCipher()
        L.init(key, 1)
        out = L.encrypt(chunks[0]) if direction == "E" else L.decrypt(chunks[0])
        return out, L.single_node_tag()

    out_parts, cvs = [], []
    for i, chunk in enumerate(chunks, start=1):
        L = LeafCipher()
        L.init(key, i)
        out_parts.append(L.encrypt(chunk) if direction == "E" else L.decrypt(chunk))
        cvs.append(L.chain_value())

    final_input = key + int.to_bytes(0, 8, "little")
    for cv in cvs:
        final_input += cv
    final_input += length_encode(n)
    final_input += SAKURA_SUFFIX
    tag = turboshake128(final_input, 0x37, TAU)
    return b"".join(out_parts), tag

def encrypt_and_mac(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, plaintext, "E")

def decrypt_and_mac(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, ciphertext, "D")
```

All leaf operations are independent and may execute in parallel. Tag computation begins as soon as all chain values are
available. `decrypt_and_mac` produces the same tag as `encrypt_and_mac` because both `encrypt` and `decrypt` write
ciphertext into the sponge rate (Section 4).

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
tw_key <- TurboSHAKE128(encode_string(K) || encode_string(N) || encode_string(AD), 0x3B, C)
```

The `encode_string` encoding (NIST SP 800-185) makes the concatenation injective: each field is prefixed with its
`left_encode`d bit-length (`left_encode(8*len(x))`), so no `(K, N, AD)` triple can produce the same TurboSHAKE128 input
as a different triple. Domain byte `0x3B` separates key derivation from all other TreeWrap128 uses of TurboSHAKE128
(`0x33`, `0x2B`, `0x27`, `0x37`).

```python
import hmac

def treewrap128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x3B, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x3B, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
```

## 6. Security Properties

This section gives a complete reduction from TreeWrap128 AEAD security to the ideal-permutation assumption on
Keccak-p[1600,12]. The argument has two layers:

- **Layer A (Section 6.4).** A single game hop replaces the TurboSHAKE128 KDF with a lazy random function, using the
  MRV15 keyed-sponge PRF security framework (Section 6.2) to bound the distinguishing advantage.
- **Layer B (Sections 6.5–6.10).** Under random keys, each AEAD goal (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) decomposes
  into keyed-sponge PRF properties of the internal functions: pseudorandomness of rate outputs, structural state
  equivalence, and fixed-key bijection.

All bounds are in the ideal-permutation model for Keccak-p[1600,12], with capacity $c = 256$ bits and $\tau = 32$ tag
bytes. Nonce-misuse resistance is explicitly out of scope: all IND-CPA and IND-CCA2 claims assume a nonce-respecting
adversary.

**Assumption scope.** Concrete bounds in this section are conditional on Keccak-p[1600,12] behaving as an ideal
permutation at the claimed workloads. This is a modeling assumption, not a proof about reduced-round Keccak-p itself.

> [!IMPORTANT]
> Public cryptanalysis on Keccak-family primitives includes reduced-round results with explicit round counts: practical
> collision-style results are publicly known through 5 rounds in standard Keccak instances, with 6-round collision
> solutions publicly reported for reduced-round contest instances, and structural distinguishers are known at higher
> round counts in the raw-permutation setting (including 8-round distinguishers and 16-round zero-sum distinguishers).
> (See the Keccak Team third-party table and reduced-round references in Section 8.)
>
> These results do not directly invalidate the TreeWrap128 heuristic because TreeWrap128 uses a keyed sponge/duplex setting
> with 256-bit capacity, strict domain separation, and workload limits; nevertheless, future cryptanalysis could change
> the practical margin, so deployments should treat the concrete bounds as conditional.

### 6.1 Model and Notation

Let:

- $\sigma$: total online Keccak-p calls performed by the construction across all oracle queries
  (including KDF, leaf-sponge, and tag-accumulation permutation calls).
- $t$: adversary offline Keccak-p calls (an analysis parameter representing direct access to the ideal
  permutation $\pi$ in the ideal-permutation model, not a deployment-controlled quantity; Section 6.14 provides
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

Let $\varepsilon_{\mathrm{ks}}(q, \ell, \mu, N)$ denote the MRV15 keyed-sponge PRF advantage bound for $q$ keyed-sponge
evaluations of at most $\ell$ input blocks each, $\mu$ total input blocks across all evaluations ($\mu \leq q\ell$),
and $N$ adversary offline $\pi$-queries. The precise expression is given in Section 6.2.

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

### 6.2 Keyed-Sponge PRF Framework (MRV15)

**Theorem (MRV15, Theorem 1).** Let $\mathrm{FKS}^{\pi}_K$ be the full keyed sponge
instantiated with an ideal permutation $\pi$ on $b$ bits, capacity $c$, and key
length $k$. For an adversary making $q$ keyed-sponge evaluations of at most
$\ell$ input blocks each, $\mu \leq q\ell$ total input blocks across all
evaluations, and $N$ offline $\pi$-queries:

$$
\mathrm{Adv}^{\mathrm{ind}}_{\mathrm{FKS}^{\pi}_K,\,\pi}(q, \ell, \mu, N)
  \;\leq\;
  \frac{2(q\ell)^2}{2^b}
  \;+\; \frac{2q^2\ell}{2^c}
  \;+\; \frac{\mu N}{2^k}.
$$

This is due to Mennink, Reyhanitabar, and Vizár (Eurocrypt 2015). For
TreeWrap128 the parameters are $b = 1600$, $c = 256$, $k = c = 256$.

**Term analysis for TreeWrap128.** The three terms have different magnitudes:

1. **Full-state birthday** $\frac{2(q\ell)^2}{2^{1600}}$: negligible at
   $b = 1600$. Even for $q\ell = 2^{128}$ this term is below $2^{-1344}$.

2. **Online-vs-online capacity term** $\frac{2q^2\ell}{2^{256}}$: scales with
   $q^2\ell$, not $q^2\ell^2$ as a naïve birthday bound would suggest. For
   TreeWrap128 leaf evaluations with $\ell \approx 49$ blocks per full
   8192-byte chunk ($\lfloor 8192/168 \rfloor + 1$), this is approximately
   $\ell/4 \approx 12\times$ tighter than the birthday bound
   $q^2\ell^2 / 2^{c+1}$ (ratio: $2q^2\ell/2^c$ vs.\ $q^2\ell^2/2^{c+1}$).

3. **Online-vs-offline term** $\frac{\mu N}{2^{256}}$: dominant when the
   adversary's offline computation budget $N$ (denoted $t$ elsewhere in this
   document) is significant. This term is linear in the total absorbed block
   count $\mu$ rather than quadratic.

**Key-loading equivalence.** MRV15's FKS (Algorithm 1) initialises with the key
placed in the capacity portion of the state: $t \gets 0^{b-k} \| K$. TreeWrap128
instead absorbs the key into the rate via standard sponge absorption: the
byte-string $K \| \mathrm{LEU64}(\mathit{index})$ is XOR'd into rate positions,
followed by pad-and-permute with domain byte $\mathtt{0x33}$. After one
ideal-permutation call, both strategies produce an equivalently unpredictable
full state. Concretely, TreeWrap128's post-init state is
$\pi(K \| \mathit{index} \| \mathtt{0x33}\text{-pad} \| 0^c)$; since $K$ is
secret and uniform, the full $\pi$-input is unique with overwhelming
probability. An ideal permutation on a unique input produces a uniformly random
output. MRV15's analysis therefore applies to the post-init sponge from this
point forward.

**Overwrite-mode coverage.** MRV15 structurally assumes XOR-absorb (FKS
Algorithm 1, line 4: $s \gets t \oplus M^i$). TreeWrap128's encrypt operation
produces identical state evolution: $\mathit{ct}[j] = \mathit{pt}[j] \oplus
S[\mathit{pos}]$ followed by $S[\mathit{pos}] \gets \mathit{ct}[j]$ yields the
same state byte as $S[\mathit{pos}] \mathrel{\oplus}= \mathit{pt}[j]$, since
$\mathit{ct}[j] = \mathit{pt}[j] \oplus S[\mathit{pos}]$ in both paths.
Overwrite mode is therefore algebraically identical to XOR-absorb for state
evolution. BDPVA11 (Section 6.2, Algorithm 5, Theorem 2) provides independent
confirmation of this equivalence.

**Squeeze-phase coverage.** MRV15's FKS includes an explicit multi-block squeeze
phase (Algorithm 1, lines 6–10) with arbitrary output length $z$. TreeWrap128's
tags ($\tau = 32$ bytes) and chain values ($C = 32$ bytes) are single-block
squeezes well within one rate block ($R = 168$ bytes). These outputs are
directly covered by Theorem 1 with $z = 1$.

> [!NOTE]
> BDPVA07 sponge indifferentiability gives
> $(\sigma + t)^2 / 2^{c+1}$ for the unkeyed sponge setting. MRV15 provides a
> tighter bound for the keyed setting that TreeWrap128 exclusively uses.
> BDPVA07 remains valid as a fallback analysis but is superseded here. The
> principal improvement is that the online-vs-online term scales with
> $q^2\ell$ rather than $q^2\ell^2$, eliminating a factor of $\ell$ from the
> dominant birthday-like term.

### 6.3 Domain Separation Lemma

**Lemma (Domain separation).** Under $\neg\mathsf{Bad}_{\mathrm{perm}}$ (Section 6.1), the construction's $\pi$-calls partition into disjoint sets by role, such that no two calls from different roles share a full 1600-bit input.

| Set | Role | Domain byte | Distinguishing mechanism |
|-----|------|-------------|--------------------------|
| $\mathcal{K}$ | KDF | `0x3B` | Padded, domain byte `0x3B` |
| $\mathcal{I}$ | Leaf init | `0x33` | Padded, domain byte `0x33` |
| $\mathcal{C}$ | Chain value | `0x2B` | Padded, domain byte `0x2B` |
| $\mathcal{T}_s$ | Single-node tag | `0x27` | Padded, domain byte `0x27` |
| $\mathcal{T}_f$ | Tag accumulation | `0x37` | Padded, domain byte `0x37` |
| $\mathcal{U}$ | Unpadded intermediate | — | Secret capacity from keyed init |

*Proof sketch.* Three cases:

1. **Padded vs. padded (different domain bytes).** The domain byte occupies a fixed position in the TurboSHAKE padding frame (byte position `pos` in `pad_permute`). Two padded blocks with different domain bytes differ in that byte position, hence have different rate content and different full $\pi$-inputs regardless of capacity.

2. **Padded vs. unpadded.** Unpadded intermediate blocks (set $\mathcal{U}$) carry no domain byte or `0x80` padding. Their capacity inputs are inherited from the keyed init chain: the initial capacity is zero; after the init `pad_permute`, the capacity output is nonzero with overwhelming probability (it is the capacity projection of $\pi$ on a fresh input); each subsequent $\pi$-call inherits the previous call's capacity output. Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, all capacity outputs are pairwise distinct across the $\sigma + t$ evaluations. The only $\pi$-call with zero capacity input is the initial state (used exclusively by padded init calls), so no unpadded block's capacity input can equal any padded block's capacity input. Combined with the rate-content difference (unpadded blocks lack domain bytes and `0x80` padding), the full 1600-bit $\pi$-inputs are distinct.

3. **Within a set.** Calls within the same role are distinguished by either different keys (different rate content at init) or different capacity inputs inherited from prior calls in the chain (guaranteed distinct under $\neg\mathsf{Bad}_{\mathrm{perm}}$).

**Sakura suffix structure.** The domain bytes are not arbitrary constants. Each encodes a Sakura suffix (ePrint 2013/231) with the structure `11 || S || R_1 R_0 || 1` (6-bit suffix, LSB-first in byte), where bit 2 is the Sakura frame bit ($S = 1$ for final-node roles, $S = 0$ for inner/leaf roles):

| Domain byte | Hex | Binary (LSB-first suffix) | Frame bit $S$ | Role type |
|-------------|-----|--------------------------|---------------|-----------|
| `0x33` | 0011 0011 | 11 **0** 01 1 | 0 | inner (leaf init) |
| `0x2B` | 0010 1011 | 11 **0** 10 1 | 0 | inner (chain value) |
| `0x3B` | 0011 1011 | 11 **0** 11 1 | 0 | inner (KDF) |
| `0x27` | 0010 0111 | 11 **0** 00 1 | 0 | final (single-node tag, $n=1$ only) |
| `0x37` | 0011 0111 | 11 **1** 01 1 | 1 | final (tag accumulation) |

Inner/final node separability follows directly from Sakura Lemma 4: the tag-accumulation domain byte (`0x37`, $S = 1$) is distinguishable from all leaf domain bytes (`0x33`, `0x2B`, $S = 0$) and the KDF byte (`0x3B`, $S = 0$) by the frame bit alone. The single-node tag byte (`0x27`) is a dedicated single-node terminal domain byte with $S = 0$; its role separation comes from its distinct domain byte value (unique among all five bytes), not from the Sakura frame bit. It appears only in the $n = 1$ path where no final node exists, so no inner/final ambiguity arises.

**Design constraint.** Future modifications to domain byte assignments MUST preserve Sakura suffix encoding compliance and the frame-bit partition between inner and final roles.

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
F(X) = \mathrm{TurboSHAKE128}(X,\;\mathtt{0x3B},\;C).
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
  tw_key <- TS128(X, 0x3B, C)         tw_key <- R(X)
  [proceed with tw_key]               [proceed with tw_key]
```

Where $\mathrm{ES} = \mathrm{encode\_string}$, $\mathrm{TS128} = \mathrm{TurboSHAKE128}$, $R$ is a lazy random
function $\{0,1\}^* \to \{0,1\}^{8C}$. The adversary's oracle access depends on the security goal (encryption oracle
for IND-CPA, encryption + decryption oracles for IND-CCA2, encryption + forgery oracle for INT-CTXT/CMT-4). The game
hop replaces only the KDF; all oracles and winning conditions are otherwise identical to the standard definitions.

**Hop justification.**

1. **Domain separation (Section 6.3).** Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, the KDF's $\pi$-calls (set
   $\mathcal{K}$, domain byte `0x3B`) are on inputs disjoint from all other components' $\pi$-calls. The KDF sponge
   evaluation is therefore functionally independent of the leaf ciphers and final-node sponge.

2. **MRV15 keyed-sponge PRF (Section 6.2).** The KDF is a keyed sponge with uniformly random master key $K$. By the
   key-loading equivalence (Section 6.2), after the init permutation the state is uniformly random. Theorem 1 applies:
   the KDF's output on distinct context strings $X$ is indistinguishable from a PRF with advantage at most
   $\varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t)$, where
   $q_{\mathrm{ctx}}$ is the number of distinct contexts, $\ell_{\mathrm{kdf}}$ is the maximum number of input blocks
   per KDF call, and $\mu_{\mathrm{kdf}}$ is the total KDF input blocks.

3. **PRF-to-RF switching.** A PRF with $q_{\mathrm{ctx}}$ queries on distinct inputs is indistinguishable from a lazy
   random function up to the birthday bound on output collisions:
   $\varepsilon_{\mathrm{ctx\text{-}coll}} \le q_{\mathrm{ctx}}^2 / 2^{8C+1}$.

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
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. The costs of these events
($\varepsilon_{\mathrm{cap}}$ and $\varepsilon_{\mathrm{ctx\text{-}coll}}$) are charged once in the bridge hop and
do not recur. Each theorem decomposes as:

$$
\mathrm{Adv}_{\Pi} \le \underbrace{\varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}}_{\text{bridge hop}} + \underbrace{\varepsilon_{\mathrm{ctx\text{-}coll}}}_{\text{key collision}} + \underbrace{\mathrm{Adv}_{\Pi}^{\mathrm{bare}}}_{\text{random-key game}},
$$

where $\mathrm{Adv}_{\Pi}^{\mathrm{bare}}$ is the advantage against the internal functions under independent uniformly
random keys.

### 6.5 Leaf Security Lemmas

> **Conditioning scope.** All analyses in Sections 6.5–6.10 work in $\mathsf{G}_1$ conditioned on
> $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. The costs of these events ($\varepsilon_{\mathrm{cap}}$
> and $\varepsilon_{\mathrm{ctx\text{-}coll}}$) are charged once in the bridge theorem (Section 6.4) and do not recur in
> subsequent sections.

Assume a fixed, uniformly random, secret key $K_{tw} \in \{0,1\}^{8C}$.

**Lemma 1 (Keyed-sponge pseudorandomness).**
For any keyed sponge initialized with `K_tw || LEU64(i)` (where $K_{tw}$ is a uniformly random secret key and $i$ is a
public index), in the ideal-permutation model, the rate outputs (keystream bytes and terminal squeeze bytes) are
pseudorandom. This holds for both overwrite-mode absorption (used by leaves) and standard XOR-mode absorption (used by
TurboSHAKE128, including the final node).

*Proof.* Each leaf is a keyed sponge with uniformly random key $K_{tw}$ (from $\mathsf{G}_1$). By the Domain Separation
Lemma (Section 6.3), under $\neg\mathsf{Bad}_{\mathrm{perm}}$, the leaf's $\pi$-calls are disjoint from all other
roles. Applying the MRV15 framework (Section 6.2) — including the key-loading equivalence and overwrite-mode coverage
established there — the PRF advantage for leaf $i$ is at most $\varepsilon_{\mathrm{ks}}(1, l_i, l_i, t)$, where $l_i$
is the number of input blocks for leaf $i$.

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

**Consequence.**
By Lemma 3 (fixed-key bijection), distinct plaintexts produce distinct ciphertexts under a fixed key, so the tag can be
viewed equivalently as a function of plaintext or ciphertext. Tag pseudorandomness is established separately in Section 6.6.

### 6.6 Tag Security

This section establishes that the tag output is pseudorandom and collision-resistant under a uniformly random key.
Section 6.6.1 establishes tag PRF security; Section 6.6.2 establishes tag collision resistance. The
$n = 1$ and $n > 1$ paths are structurally parallel: both are keyed sponge instances with distinct indices
(Section 5). They are analyzed separately below, but the bound is the same in both cases.

#### 6.6.1 Tag PRF Security

**Case $n = 1$.** The tag is `single_node_tag()`: a direct squeeze from the leaf's overwrite-mode keyed sponge (index 1)
with domain byte 0x27 (see Section 5 for the construction). By Lemma 1, this output is pseudorandom up to
$\varepsilon_{\mathrm{ks}}(1, l_1, l_1, t)$, where $l_1$ is the number of input blocks for the single leaf.

**Case $n > 1$.** The final node is a keyed sponge: it is a TurboSHAKE128 call whose input begins with
$K_{tw} \| \mathrm{LEU64}(0)$ (see Section 5, final-node computation). Leaves use indices 1 through $n$; the final
node uses index 0. All init inputs are therefore distinct.

By Lemma 1 (generalized to XOR-absorb mode), the final node's rate outputs are pseudorandom. By the Domain Separation
Lemma (Section 6.3), the final-node domain byte 0x37 (Sakura frame bit $S=1$) is distinct from all leaf domain bytes
($S=0$). Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, the final node's $\pi$-calls are disjoint from all leaf
$\pi$-calls. The tag is a squeeze from this keyed sponge — pseudorandom by Lemma 1.

Combining both cases:

$$
\varepsilon_{\mathrm{prf}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{tag}}, \ell_{\mathrm{tag}}, \mu_{\mathrm{tag}}, t),
$$

where $q_{\mathrm{tag}}$, $\ell_{\mathrm{tag}}$, and $\mu_{\mathrm{tag}}$ are the number of keyed-sponge evaluations,
maximum input blocks per evaluation, and total input blocks for the tag computation, respectively.

#### 6.6.2 Tag Collision Resistance

For $Q$ AEAD outputs (each a ciphertext-tag pair, as defined in Section 6.1) under one fixed secret key:

$$
\varepsilon_{\mathrm{coll}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{tag}}, \ell_{\mathrm{tag}}, \mu_{\mathrm{tag}}, t) + \frac{Q^2}{2^{8\tau+1}}.
$$

The $\varepsilon_{\mathrm{cap}}$ term accounts for the event $\mathsf{Bad}_{\mathrm{perm}}$ (which is conditioned
away in the $Q^2/2^{8\tau+1}$ term); combining these via a union bound gives the unconditional bound.
Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$, tags are pseudorandom $\tau$-byte outputs (Section 6.6.1). The
second term is the birthday bound on collisions among $Q$ approximately independent, uniformly random $8\tau$-bit
strings.

Within a single derived key: distinct plaintexts produce distinct ciphertexts (Lemma 3). For $n = 1$, distinct
ciphertexts produce distinct sponge state evolutions and hence distinct tag-squeeze inputs. For $n > 1$, distinct
ciphertexts in at least one chunk produce at least one different chain value (Lemma 3 + ideal permutation on distinct
inputs). The final node absorbs different data; under $\neg\mathsf{Bad}_{\mathrm{perm}}$, its capacity state diverges,
producing a unique tag-squeeze input. Either way, the ideal permutation on distinct inputs produces approximately
independent uniform outputs.

Across different derived keys: distinct keys produce different init absorptions, hence different capacity states after
the first permutation call. With no capacity collision between any pair of $\pi$-calls
($\neg\mathsf{Bad}_{\mathrm{perm}}$), the two tag computations query $\pi$ at disjoint inputs, producing approximately
independent uniform outputs (see the PRP/PRF convention in Section 6.1).

Combining both cases: for any pair of distinct AEAD outputs $(i, j)$ (whether within-key or cross-key),
$\Pr[T_i = T_j] \leq 2^{-8\tau}$.
The birthday bound over all $\binom{Q}{2}$ pairs then gives the $Q^2/2^{8\tau+1}$ term.

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
  Lemma 1, Section 6.5), showing that each ciphertext block is uniformly distributed regardless of the plaintext:
  - *Block 0:* The `init` step absorbed the truly random key $K_{tw}$ and applied $\pi$ via `pad_permute` (one
    permutation call); the resulting state is uniformly random (see Lemma 1, Section 6.5). The first rate block of
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

Therefore:

$$
\varepsilon_{\mathrm{ind\text{-}cpa}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}}.
$$

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
forgery attempt targets a context with a uniformly random key. The tag is a pseudorandom $\tau$-byte value (by
Lemma 1, Section 6.5, and Section 6.6). Each forgery attempt — i.e., a (ciphertext, tag) pair not previously output by the
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
\varepsilon_{\mathrm{int\text{-}ctxt}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}} + \frac{S}{2^{8\tau}}.
$$

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

**Step 3: Lift through bridge theorem.** Applying the decomposition from Section 6.4:

$$
\varepsilon_{\mathrm{ind\text{-}cca2}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}} + \frac{S}{2^{8\tau}}.
$$

> *Note on construction type.* TreeWrap128 is structurally an encrypt-and-MAC scheme (the tag is derived from the
> same sponge state as the ciphertext), not an Encrypt-then-MAC scheme with independent keys. The BN00 composition
> theorem (Theorem 4.3) is a general result: it states that *any* symmetric encryption scheme satisfying both IND-CPA
> and INT-CTXT also satisfies IND-CCA2. The theorem's only preconditions are these two properties of the composed
> scheme, not any requirement on its internal structure (e.g., independent keys or separate MAC). Sections 6.7 and 6.8
> establish IND-CPA and INT-CTXT for TreeWrap128 directly, so the theorem applies. The overwrite-mode sponge ensures
> that the tag depends on the ciphertext (ciphertext bytes are written into the rate before the tag squeeze), which is
> why INT-CTXT holds despite the shared state.

Nonce reuse for the same $(K,N,AD)$ is out of scope for this claim and breaks standard nonce-respecting
IND-CCA2 formulations.

### 6.10 CMT-4 (Fixed Master Key)

This theorem follows the standard Bellare-Hoang committing-security notion (CMT-4, see Section 8): a ciphertext should not
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

As in Section 6.7, move to $\mathsf{G}_1$ where context-to-key derivation is replaced by a lazy random function and pay
$\varepsilon_{\mathrm{cap}}$ plus $\varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t)$.

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
  produces tag $T^\star$ on $\mathit{ct}^\star$. By tag PRF security (Section 6.6.1), this second tag is approximately
  uniform over $\{0,1\}^{8\tau}$ and independent of the first, so the match probability is at most $2^{-8\tau}$ per
  candidate context. Over at most $Q$ candidate contexts (encryption-oracle queries plus the two openings), the union
  bound gives $\Pr[\text{match}] \leq Q / 2^{8\tau}$.

Therefore:

$$
\varepsilon_{\mathrm{cmt4}} \le \varepsilon_{\mathrm{cap}} + \varepsilon_{\mathrm{ks}}(q_{\mathrm{ctx}}, \ell_{\mathrm{kdf}}, \mu_{\mathrm{kdf}}, t) + \varepsilon_{\mathrm{ctx\text{-}coll}} + \frac{Q}{2^{8\tau}}.
$$

Here $Q$ (as defined in Section 6.1) counts all AEAD outputs in the experiment. For $\tau = 32$, the denominator is
$2^{256}$.

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
- Truncation/extension changes chunk count $n$, changing `length_encode(n)` in final accumulation input.
- Empty plaintext uses $n=1$: one leaf with `single_node_tag()`, no final accumulation node.

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
- Enforce nonce uniqueness per key epoch (deterministic nonces such as counters/sequences are RECOMMENDED; random-nonce
  deployments SHOULD use a large nonce space, e.g., 192 or 256 bits).
- For deterministic nonces, choose $q_{\mathrm{enc,cap}}$ so nonce values cannot wrap or repeat within the epoch.
- If random nonces are used, additionally enforce
  $q_{\mathrm{nonce}}(q_{\mathrm{nonce}}-1)/2^{b+1} \le p_{\mathrm{nonce}}$ for nonce bit-length $b$ and chosen nonce-collision target
  $p_{\mathrm{nonce}}$.
- Define and enforce a failed-verification budget $S_{\mathrm{cap}}$ per key epoch. If $S > S_{\mathrm{cap}}$,
  implementations MUST stop accepting further decryption attempts for that epoch and rotate to a fresh key epoch before
  resuming.
- On any cap exceedance (workload, invocation, nonce, or failed-verification policy), implementations MUST rotate to a
  fresh key epoch before any further encryption.

Analysis interpretation (normative for this profile): evaluate the Section 6 bounds using default offline-work profile
$t = 2^{64}$.

Expert profile (non-normative): deployments with stronger review/monitoring may choose workload caps above $2^{60}$, up
to $2^{64}$, using the same counter model.

Security interpretation remains the Section 6 bound family evaluated at observed counters, with adversary offline budget
parameter $t$ treated as an analysis parameter (not an operationally measurable quantity).

For deployments spanning multiple master keys/users in one reporting window, estimate total risk by summing per-key
epoch bound values over that window (union bound).

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

The following implementation decisions are performance-critical and align with high-throughput production designs:

- **Batch leaves by SIMD width.** Process complete chunks in vector batches (for example, x4 then x2 then x1) to keep
  permutation backends saturated.
- **Use runtime-dispatched Keccak backends.** Provide architecture-specific permutation paths and dispatch at runtime:
  amd64 (AVX-512/AVX2/SSE2), arm64 (FEAT_SHA3 where available), with a constant-time scalar fallback for portability.
- **Match scheduling to permutation kernels.** Structure worker loops so the hot path maps directly onto `P1600x4`,
  then `P1600x2`, then `P1600`, minimizing tail overhead and avoiding per-block feature checks inside inner loops.
- **Parallelize independent finalizations when available.** If two independent TurboSHAKE/Keccak states must be
  finalized together, use a paired permutation path (`x2`) to reduce permutation-call overhead.
- **Stream chain values incrementally.** Feed chain values into a running TurboSHAKE128 hasher as each batch completes;
  only finalization depends on having absorbed all chain values.
- **Preserve empty/single-chunk fast paths.** Keep dedicated empty-input and `n = 1` paths to avoid
  unnecessary tree-accumulation overhead on latency-sensitive inputs.
- **Use incremental stateful processing.** Maintain chunk-local state across partial writes/reads so callers can stream
  large messages without extra buffering copies.
- **Reuse one scheduling pipeline for both directions.** Encrypt and decrypt should share the same chunk scheduling,
  index binding, and chain-value accumulation pipeline.
- **Keep domain bytes and index mapping exact.** `0x33`, `0x2B`, `0x3B`, `0x27`, `0x37` constants and `key || LEU64(index)` binding (index 0
  for the final node, indices 1..$n$ for leaves) are structural for interoperability and security analysis.
- **Treat reference code as correctness-first.** For production throughput, avoid repeated byte-string concatenation
  patterns when constructing final-node inputs.

## 8. Comparison with Traditional AEAD

TreeWrap128 differs from traditional AEAD in several respects.

**Nonce-free internal primitive.** The internal encrypt-and-MAC functions take only a key and data. Nonces are consumed
by the TurboSHAKE128-based KDF to derive a unique internal key, not passed to the encrypt/MAC layer itself.

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs -- they prove authenticity but are not
necessarily pseudorandom. TreeWrap128's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (Section 6.6.1). This stronger property is useful for protocols that derive further keying material from the tag.

### 8.1. Operational Safety Limits

Operational planning assumptions used in this section: $p = 2^{-50}$, 1500-byte messages, TreeWrap128 cost
$\approx 11$ Keccak-p calls/message (1 KDF + 10 leaf calls), $\ell \approx 49$ max input blocks per keyed-sponge
evaluation, and per-key accounting (single key / key epoch). Figures are conditional on the Section 6 model assumptions
for Keccak-p[1600,12] and the selected offline-work profile.

Under the MRV15 keyed-sponge PRF framework (Section 6.2), the dominant online-online term is $2q^2\ell / 2^c$. For a
conservative estimate, set $q$ to the number of TreeWrap128 encryptions and $\ell = 49$ (worst-case blocks absorbed per
message, which overstates the per-evaluation input length and is therefore safe). With $c = 256$ and target
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

Configured usage limits SHOULD be driven by nonce policy and key-epoch rotation controls (Section 6.14), not by the asymptotic
proof-bound figure alone.

## 9. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007. Establishes
  the flat sponge claim (sponge indifferentiability from a random oracle). Referenced in the non-normative note in
  Section 6.2.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint
  2013/231. Defines the tree hash coding framework used by KangarooTwelve and TreeWrap128.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., and Van Keer, R. "TurboSHAKE." IACR ePrint 2023/342.
  Primary specification and design rationale for TurboSHAKE.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., and Van Keer, R. "KangarooTwelve: fast hashing based on
  Keccak-p." IACR ePrint 2016/770. Security and design context for the Sakura-based tree structure.
- Keccak Team. "Third-party cryptanalysis." https://keccak.team/third_party.html. Curated summary table of published
  cryptanalysis results and round counts across Keccak-family modes and raw permutations.
- Maurer, U., Renner, R., and Holenstein, C. "Indifferentiability, Impossibility Results on Reductions, and
  Applications to the Random Oracle Methodology." TCC 2004. Introduces indifferentiability and the core composition
  theorem framework used for random-oracle replacement arguments.
- Coron, J.-S., Dodis, Y., Malinaud, C., and Puniya, P. "Merkle-Damgård Revisited: How to Construct a Hash Function."
  CRYPTO 2005. Applies the MRH indifferentiability composition theorem to hash function constructions; referenced in the
  non-normative note in Section 6.4.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.
- Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the Generic
  Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2; used in Section 6.9.
- Namprempre, C., Rogaway, P., and Shrimpton, T. "Reconsidering Generic Composition." EUROCRYPT 2014. Extends the
  BN00 composition theorem to the nonce-based setting; used in Section 6.9.
- Ristenpart, T., Shacham, H., and Shrimpton, T. "Careful with Composition: Limitations of the Indifferentiability
  Framework." Eurocrypt 2011 (ePrint 2011/339 as "Limitations of Indifferentiability and Universal Composability").
  Highlights multi-stage composition caveats; motivates explicit game-hop arguments in composed proofs.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass Authenticated Encryption
  and Other Applications." SAC 2011. IACR ePrint 2011/499. Proves that duplex outputs are pseudorandom under the sponge
  indifferentiability assumption (Theorem 1) and gives overwrite-mode security (Section 6.2, Algorithm 5, Theorem 2:
  Overwrite is as secure as Sponge); establishes that all intermediate rate outputs -- not just terminal squeezes -- are
  covered by the duplex security bound.
- Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex: Beyond the Birthday
  Bound." Eurocrypt 2015. Primary security framework for TreeWrap128. Proves beyond-birthday-bound security for the
  keyed sponge/duplex in the ideal-permutation model (Theorem 1). Used throughout Section 6.
- Dinur, I., Dunkelman, O., and Shamir, A. "Improved practical attacks on round-reduced Keccak." Journal of
  Cryptology 27(2), 2014. Reports practical 4-round collisions and 5-round near-collision results in standard
  Keccak-224/256 settings.
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
| tag | `75c535a63e00491b6a63871da0e3c430bb42688ceb8ba05543e96386d55564b4` |

#### 10.1.2 One-Byte Plaintext (n = 1)

| Field | Value |
|-------|-------|
| len | 1 |
| ct | `fe` |
| tag | `a4fd753dd0787e772b08db6f1c9b0a6cc4864ed390784d5d65f037a4f708346c` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`c5b46e7da8de3ceb1801b4b3f800ee52b06419e224de77967a11994166c66954`.

#### 10.1.3 B-Byte Plaintext (exactly one chunk, n = 1)

| Field | Value |
|-------|-------|
| len | 8192 |
| ct[:32] | `fe0aebeee41a66a6e3284247150dad651507b60cde3a23448df00abe9b47f029` |
| tag | `d44d8a31f0c566c370dbd49d45de196265a809d68ee3cb54e1df3db8b42ba81a` |

Flipping bit 0 of `ct[0]` yields tag
`c38c6774775e4ddb5d338ac439bcf1654f40b4916901043a992f51c5bb0c5d91`.

#### 10.1.4 B+1-Byte Plaintext (two chunks, minimal second, n = 2)

| Field | Value |
|-------|-------|
| len | 8193 |
| ct[:32] | `fe0aebeee41a66a6e3284247150dad651507b60cde3a23448df00abe9b47f029` |
| tag | `3f0314010ba842961c0f300702bf3b5eac18dba67ba4214654c7e2db72e0c30b` |

Flipping bit 0 of `ct[0]` yields tag
`434be033d300ea9ac7a4881d509e21d20db7a2e437b159e152c776d16a5fe8c4`.

#### 10.1.5 4B-Byte Plaintext (four full chunks, n = 4)

| Field | Value |
|-------|-------|
| len | 32768 |
| ct[:32] | `fe0aebeee41a66a6e3284247150dad651507b60cde3a23448df00abe9b47f029` |
| tag | `1018618a8e8f25e39f347db71f01e582803e802dce9afaef70f90be32d8b497c` |

Flipping bit 0 of `ct[0]` yields tag
`f2d1991095c7fe59cc5ff5d53f0bf9f0b76b0ae78202d4827e662688f8862798`.

Swapping chunks 0 and 1 (bytes 0-8,191 and 8,192-16,383) yields tag
`704270ad357c5a68a9f59b0f087f759d87a134b0f67f1cfcfe63f46a7f8ab985`.

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
| ct‖tag | `acdce0015a3ffe523fe241c4b0616a1744c9df604b36b812d769692cf3c8116f` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.2 33-Byte Message With 5-Byte AD

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `a0 a1 a2 ... ab` |
| AD | 10 11 12 ... 14 |
| M len | 33 (`00 01 02 ... mod 256`) |
| ct‖tag | `0f7ef046cf60a9a7b457d4306d4f27cf3dafe0c1ce3de5a573e916fda2f523a6b4533abe4d32c9cab83c2e05cc9d0648a43a47a373ba9b73a6ce173590037c3822` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.3 Multi-Chunk Message (8193 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `42 43 44 ... 61` |
| N | 12 bytes `c0 c1 c2 ... cb` |
| AD | 00 01 02 ... 10 |
| M len | 8193 (`00 01 02 ... mod 256`) |
| ct[:32] | `26b8fcc6d51833746cdb315036e8ffe2d45b34b5fde25a429f8c2856975cdbbd` |
| tag | `0ab96f8f19ba6527916c1ddd8913b8c2d62723d51dbc6406694b8b37408604c1` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 10.2.4 Nonce Reuse Behavior (Equal-Length Messages)

| Field | Value |
|-------|-------|
| K | 32 bytes `00 11 22 ... ff` |
| N | 12 bytes `ff ee dd cc bb aa 99 88 77 66 55 44` |
| AD | a1 a2 a3 ... a4 |
| M len | 64 (`00 01 02 ... mod 256`) |
| ct‖tag | `12ecaa6ac37cecdb235a56f0f47d41f66c11bcd718d446bf66dfb89afbf716f7ba7b744570778c82cfcbd1b5753ed4798b8199891b361aca990dc0acd4dbf3c38d8604ceac0f6ee97aa94e9326aa8310251aec6e67cc22986cf298b6b17c70d0` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Reusing the same `(K, N, AD)` with a different message is deterministic and yields
`ct1 xor ct2 = m1 xor m2` for equal-length messages (validated by this vector).
Nonce reuse is out of scope for Section 6 nonce-respecting claims.

#### 10.2.5 Swapped Nonce and AD Domains

| Field | Value |
|-------|-------|
| K | 32 bytes `0f 0e 0d ... 00` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | 10 11 12 ... 1b |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `b01289d7720b07a06a3c2fd4022bb4b17b8dd6446889499bb3a7dbefd6ea2199ed89f592727685ad34d0a3a0f2e809939d991655392bd353a8b48c999b6c1056d22b5a1ce2c436069f6d82cb9faaca7a` |

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
| ct‖tag | `75c8ffb697d1118550c83650032d1094c8f89ee84311f981735d1960f050eac2afed5c0a18e9d1a0d903479e83bf0b9fc73a499dc7838836df1b1821d190034f` |

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
| ct‖tag | `0a611a56065902161736588f3f5aee00d4be61895a55c1996550fefb486ad366dc953f7868324e5674a650e4a5b24e2a6b` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

## Appendix A. Exact Per-Query $\sigma$ Formula

For a single `TreeWrap128` query on a message of length $L$ bytes with
$n = \max(1, \lceil L / B \rceil)$ chunks of sizes $\ell_1, \ldots, \ell_{n}$, the per-query contribution to
$\sigma$ is:

$$\sigma_{\mathrm{query}} = \underbrace{\left(\left\lfloor \frac{|\mathit{kdf\_input}|}{R} \right\rfloor + 1\right)}_{\text{KDF}} + \underbrace{\sum_{i=1}^{n}\left(2 + \left\lfloor \frac{\ell_i}{R} \right\rfloor\right)}_{\text{leaves}} + \underbrace{\mathbb{1}_{n>1} \cdot \left(\left\lfloor \frac{|\mathit{final\_input}|}{R} \right\rfloor + 1\right)}_{\text{tag accumulation}}$$

where:

- **KDF term.** $|\mathit{kdf\_input}|$ is the byte length of
  `encode_string(K) || encode_string(N) || encode_string(AD)`.
  Each `encode_string` contributes `left_encode(8|x|)` (2-3 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $|\mathit{kdf\_input}| = (3+32) + (2+12) + (2+0) = 51$ bytes, giving
  $\lfloor 51 / 168 \rfloor + 1 = 1$ Keccak-p call.
  (The `+1` accounts for TurboSHAKE's pad+permute step even when the absorb phase ends exactly on a rate boundary.)
- **Leaf term.** Each leaf costs $2$ (init `pad_permute` + terminal `pad_permute` for `single_node_tag` or
  `chain_value`) $+$ $\lfloor \ell_i / R \rfloor$ (unpadded intermediate permutations on full-rate blocks). For a
  full $B = 8192$-byte chunk: $2 + \lfloor 8192 / 168 \rfloor = 2 + 48 = 50$.
- **Tag accumulation term.** Present only
  when $n > 1$. $|\mathit{final\_input}| = (C + 8) + nC + |\mathrm{length\_encode}(n)| + 2$ bytes (the $C + 8 = 40$
  byte key-and-index prefix, plus $n$ chain values and the Sakura suffix).
  For $n = 2$: $|\mathit{final\_input}| = 40 + 64 + 2 + 2 = 108$ bytes, giving
  $\lfloor 108 / 168 \rfloor + 1 = 1$.

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
This is the same $\sigma_{\mathrm{total}}$ counter model used normatively in Section 6.14.

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
