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

| Byte   | Usage                        | Procedure(s)                     |
|--------|------------------------------|----------------------------------|
| `0x60` | Init (key/index absorption)  | `init`                           |
| `0x61` | Single-node tag squeeze      | `single_node_tag`                |
| `0x62` | Final block (chain value)    | `chain_value`                    |
| `0x63` | Tag accumulation             | `EncryptAndMAC`, `DecryptAndMAC` |
| `0x64` | AEAD key derivation          | `TreeWrap128`                    |

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
                self.pad_permute(0x60)
        self.pad_permute(0x60)

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
        self.pad_permute(0x61)
        return bytes(self.S[:TAU])

    def chain_value(self) -> bytes:
        self.pad_permute(0x62)
        return bytes(self.S[:C])
```

> [!NOTE]
> `pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at $R-1$). `init` uses domain byte
> `0x60`; `chain_value` uses `0x62`; `single_node_tag` uses `0x61`. Intermediate encrypt/decrypt blocks use the full
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
final node `'1'` -- are not encoded as explicit data bytes; final-node separability (Sakura Lemma 4) is ensured by the
TurboSHAKE128 domain byte `0x63`, which is distinct from all leaf cipher domain bytes (`0x60`-`0x62`).

The `0xFF || 0xFF` suffix is defined as `SAKURA_SUFFIX` in the reference code (Section 5.1).

**Domain separation.** The key prefix makes the final node a keyed sponge: its TurboSHAKE128 input begins with
`key || LEU64(0)`, XOR-absorbed into the rate before any chain values. Leaves absorb `key || LEU64(i)` for $i \geq 1$
via the LeafCipher `init` method (domain byte `0x60`). The final node's first 40 absorbed bytes therefore differ from
every leaf's (index 0 vs. index $\geq 1$), and domain byte `0x63` is distinct from leaf domain bytes (`0x60`-`0x62`),
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
    tag = turboshake128(final_input, 0x63, TAU)
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

**Master-key requirement.** `K` MUST have at least 128 bits of min-entropy and MUST be at least 16 bytes long. Uniformly
random 32-byte keys are RECOMMENDED.

**Key derivation:**

```
tw_key <- TurboSHAKE128(encode_string(K) || encode_string(N) || encode_string(AD), 0x64, C)
```

The `encode_string` encoding (NIST SP 800-185) makes the concatenation injective: each field is prefixed with its
`left_encode`d bit-length (`left_encode(8*len(x))`), so no `(K, N, AD)` triple can produce the same TurboSHAKE128 input
as a different triple. Domain byte `0x64` separates key derivation from all other TreeWrap128 uses of TurboSHAKE128
(`0x60` - `0x63`).

```python
import hmac

def treewrap128_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x64, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap128_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x64, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
```

## 6. Security Properties

This section gives a complete reduction from TreeWrap128 AEAD security to the ideal-permutation assumption on
Keccak-p[1600,12]. The argument has two layers:

- **Layer A (Section 6.2).** A single game hop replaces the TurboSHAKE128 KDF with a lazy random function, reducing AEAD
  security to the security of the internal functions under independent, uniformly random per-context keys.
- **Layer B (Sections 6.3–6.8).** Under random keys, each AEAD goal (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) decomposes
  into explicit properties of keyed sponge instances (overwrite-mode leaves and the XOR-absorb final node):
  pseudorandomness of rate outputs, structural state equivalence, and fixed-key bijection.

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
  permutation $\pi$ in the ideal-permutation model, not a deployment-controlled quantity; Section 6.12 provides
  operational guidance on choosing $t$ for bound evaluation).
- $S$: total number of decryption/verification forgery attempts in one security experiment (per key epoch).
- $Q$: total number of AEAD outputs (encryption-oracle responses plus any outputs the adversary compares in a forgery or
  commitment game) in one security experiment (per key epoch); each encryption-oracle response (ciphertext + tag) counts
  as one AEAD output. Used in birthday-style collision bounds.
- $q_{\mathrm{ctx}}$: number of distinct context strings $X$ queried to the KDF in one security experiment.
- $n = \max(1, \lceil |M|/B \rceil)$: number of chunks for a message of length $|M|$.
- Throughout Section 6, $c = 8C = 256$ denotes the capacity in bits.

Throughout this section, "capacity state," "capacity output," and "capacity projection" all refer to the 256-bit
low-order portion of the 1600-bit Keccak-p state.

Unless stated otherwise, these symbols are scoped to one fixed master key (one key epoch / one experiment instance).

Define the common structural term:

$$
\varepsilon_{\mathrm{indiff}} \;\stackrel{\mathrm{def}}{=}\; \frac{(\sigma + t)^2}{2^{c+1}}.
$$

This is the standard sponge indifferentiability bound (BDPVA07). **The quantity $\sigma + t$ counts all Keccak-p
evaluations globally -- across all five domain-byte roles (0x60–0x64, assigned in Section 4), unpadded intermediate encrypt/decrypt
permutations, and the adversary's offline permutation queries -- so it is charged once and covers all components
simultaneously.** Because $\mathsf{Bad}_{\mathrm{perm}}$ (Section 6.2) is defined over all $\sigma + t$ evaluations
regardless of domain byte, a single $\varepsilon_{\mathrm{indiff}}$ charge covers all sponge roles. Domain separation
ensures that absent $\mathsf{Bad}_{\mathrm{perm}}$, each role's capacity states are disjoint from every other role's.

### 6.2 Bridge Theorem: KDF to Random Key

This section executes the single game hop that replaces the TurboSHAKE128 KDF with a lazy random function. The
derived-key outputs are then consumed by the leaf-level security lemmas in Section 6.3.

Define the AEAD context encoding:

$$
X = \mathrm{encode\_string}(K)\,\|\,\mathrm{encode\_string}(N)\,\|\,\mathrm{encode\_string}(AD),
$$

and the derived-key map:

$$
F(X) = \mathrm{TurboSHAKE128}(X,\;0x64,\;C).
$$

**Games.**

- Game $\mathsf{G}_0$: real `TreeWrap128`, i.e., per-context key $F(X)$.
- Game $\mathsf{G}_1$: replace $F$ with a lazy-sampled random function $R:\{0,1\}^* \to \{0,1\}^{8C}$ on contexts.
  Only the KDF invocation is replaced; all leaf ciphers and the final-node keyed TurboSHAKE128 continue to call the
  shared ideal permutation $\pi$.

The adversary's oracle access depends on the goal: encryption oracle for IND-CPA; encryption + decryption oracles for
IND-CCA2; encryption + forgery oracle for INT-CTXT/CMT-4. The game hop replaces only the KDF; all oracles and winning
conditions are otherwise identical to the standard definitions.

**Domain separation.** The KDF uses domain byte 0x64, which is exclusive to the KDF among the five domain bytes
(0x60–0x64). Absent a capacity-part collision, KDF sponge absorptions produce capacity states distinct from those of
any internal leaf or tag-accumulation computation (different domain bytes yield different padded blocks — the domain byte
occupies a fixed position in the TurboSHAKE padding frame, so two absorptions with distinct domain bytes always differ
in their final padded byte — hence different permutation inputs). Intermediate encrypt/decrypt blocks use unpadded
permutations (no domain byte); their capacity states are distinguished from padded roles by the secret capacity derived
from the keyed init, not by rate-level domain separation. Cross-component capacity collisions can occur only under
$\mathsf{Bad}_{\mathrm{perm}}$. The probability of $\mathsf{Bad}_{\mathrm{perm}}$ is bounded by
$\varepsilon_{\mathrm{indiff}}$ independently of the domain-separation property (it is a birthday bound over
$\sigma + t$ random permutation outputs).

**Hop justification.** Let $\mathsf{Bad}_{\mathrm{perm}}$ be the event that the ideal permutation exhibits a
capacity-part collision among any pair of the $\sigma + t$ total evaluations (online construction calls and adversary
offline calls). A *capacity-part collision* occurs when two distinct Keccak-p evaluations produce equal 256-bit capacity
outputs (the low $c$ bits of the 1600-bit state). By the birthday bound,
$\Pr[\mathsf{Bad}_{\mathrm{perm}}] \leq \binom{\sigma+t}{2} \cdot 2^{-c} \leq (\sigma+t)^2/2^{c+1} = \varepsilon_{\mathrm{indiff}}$.
Because the capacity output of one permutation call becomes the
capacity input to the next call (with fresh rate data overwritten or XORed into the rate portion), no capacity-output
collision implies no capacity-input collision for any subsequent call — the two properties are equivalent in the
sponge/duplex setting. This equivalence is used throughout Sections 6.3–6.8, where arguments about "fresh permutation
inputs" and "distinct capacity states" both follow from $\neg\mathsf{Bad}_{\mathrm{perm}}$.

Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, all *construction-generated* $\pi$-calls (KDF, leaf sponges, final-node
TurboSHAKE128) have pairwise distinct capacity states: each call's capacity input is the capacity output of the
preceding call (by the capacity-preservation property above), and $\neg\mathsf{Bad}_{\mathrm{perm}}$ guarantees no
capacity-output collision. Since the capacity occupies a fixed 256-bit subset of the 1600-bit state, two inputs with
distinct capacity portions are necessarily distinct as 1600-bit strings, so every construction-generated $\pi$-call has
a unique input. The ideal permutation on these unique inputs produces individually uniform outputs.

$\mathsf{Bad}_{\mathrm{perm}}$ covers all $\binom{\sigma+t}{2}$ pairs, including adversary-vs-construction pairs. Under
$\neg\mathsf{Bad}_{\mathrm{perm}}$, adversary offline queries also have capacity outputs distinct from construction
capacity outputs. However, unlike construction-generated queries (whose capacity *inputs* are secret), the adversary
can freely choose its query inputs. The adversary's ability to *target* construction capacity states is limited by
secrecy: each construction capacity state is a 256-bit output of a previous $\pi$-call, unknown to the adversary. The
probability that any of the adversary's $t$ offline queries matches any of the $\sigma$ construction capacity inputs
is at most $t\sigma / 2^c$ (union bound). For init calls specifically, the capacity input is zero (public), but the
rate contains the secret key $K_{tw}$, so each adversary query matches a specific init call's *full input* with
probability at most $2^{-8C}$ (guessing the key portion). Both costs are absorbed by
$\varepsilon_{\mathrm{indiff}}$ since $t\sigma/2^c \leq (\sigma+t)^2/2^{c+1}$.

The game hop is justified by MRH composition (Maurer-Renner-Holenstein, TCC 2004; applied to indifferentiability by
Coron-Dodis-Malinaud-Puniya, CRYPTO 2005). TurboSHAKE128 is sponge-indifferentiable from a random oracle (BDPVA07);
MRH composition guarantees that replacing TurboSHAKE128 with a lazy random function in any single-stage game costs at
most the indifferentiability bound. The AEAD security games (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) are single-stage, so
the hop is justified. Only the KDF invocation is replaced; all leaf ciphers and the final-node sponge retain their
original access to the shared ideal permutation $\pi$.

The indifferentiability bound $\varepsilon_{\mathrm{indiff}}$ is defined over the total evaluation count $\sigma + t$
(all $\pi$-calls: KDF, leaves, tag accumulation, and adversary offline queries), so no additional per-component charge
is needed. By MRH composition, the game hop gap is bounded by the TurboSHAKE128 indifferentiability bound:

$$
\left|\Pr[\mathsf{G}_0=1]-\Pr[\mathsf{G}_1=1]\right| \le \varepsilon_{\mathrm{indiff}} = \frac{(\sigma+t)^2}{2^{c+1}},
$$

where $\varepsilon_{\mathrm{indiff}}$ is the concrete sponge indifferentiability bound from BDPVA07, numerically equal to the capacity birthday bound. The event
$\mathsf{Bad}_{\mathrm{perm}}$ satisfies $\Pr[\mathsf{Bad}_{\mathrm{perm}}] \le \varepsilon_{\mathrm{indiff}}$ as a
consequence: the probability that any pair among $\sigma + t$ ideal-permutation evaluations produces a capacity-part
collision is bounded by the same birthday term. This identification is used in later sections when conditioning on
$\neg\mathsf{Bad}_{\mathrm{perm}}$.

> [!NOTE]
> The Ristenpart-Shacham-Shrimpton (RSS11) result shows that indifferentiability does not compose in multi-stage games.
> TreeWrap128's AEAD security games (IND-CPA, INT-CTXT, IND-CCA2, CMT-4) are all single-stage: the adversary runs in
> one stage with oracle access and produces a single output. The RSS caveat therefore does not apply here. The explicit
> game hop above is not a workaround for RSS; it is the standard application of indifferentiability composition to a
> single-stage game.

With the game hop established, the remaining analysis works entirely in $\mathsf{G}_1$ and addresses key collisions
among distinct contexts.

**Context collisions.** Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$ in $\mathsf{G}_1$, contexts map as a lazy
random function on distinct strings $X$. For $q_{\mathrm{ctx}}$ distinct contexts, the probability of a derived-key collision is bounded by:

$$
\varepsilon_{\mathrm{ctx\text{-}coll}} \le \frac{q_{\mathrm{ctx}}^2}{2^{8C+1}}.
$$

This is the standard birthday bound for a lazy random function with range $\{0,1\}^{8C}$.
Let $\mathsf{CtxColl}$ denote this event (a derived-key collision among distinct contexts).

This context-collision term is per experiment/per key epoch; multi-key or multi-user deployment totals are obtained by
summing per-key-epoch probabilities (union bound).

**Summary.** All AEAD goals below (Sections 6.5–6.8) are analyzed in $\mathsf{G}_1$, conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. The costs of these events
($\varepsilon_{\mathrm{indiff}}$ and $\varepsilon_{\mathrm{ctx\text{-}coll}}$) are charged once in the bridge hop and
do not recur. Each theorem decomposes as:

$$
\mathrm{Adv}_{\Pi} \le \underbrace{\varepsilon_{\mathrm{indiff}}}_{\text{bridge hop}} + \underbrace{\varepsilon_{\mathrm{ctx\text{-}coll}}}_{\text{key collision}} + \underbrace{\mathrm{Adv}_{\Pi}^{\mathrm{bare}}}_{\text{random-key game}},
$$

where $\mathrm{Adv}_{\Pi}^{\mathrm{bare}}$ is the advantage against the internal functions under independent uniformly
random keys, bounded explicitly for each goal.

### 6.3 Leaf Security Lemmas

> **Conditioning scope.** All analyses in Sections 6.3–6.8 work in $\mathsf{G}_1$ conditioned on
> $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$. The costs of these events ($\varepsilon_{\mathrm{indiff}}$
> and $\varepsilon_{\mathrm{ctx\text{-}coll}}$) are charged once in the bridge theorem (Section 6.2) and do not recur in
> subsequent sections.

Assume a fixed, uniformly random, secret key $K_{tw} \in \{0,1\}^{8C}$.

**Lemma 1 (Keyed-sponge pseudorandomness).**
For any keyed sponge initialized with `K_tw || LEU64(i)` (where $K_{tw}$ is a uniformly random secret key and $i$ is a
public index), in the ideal-permutation model, the rate outputs (keystream bytes and terminal squeeze bytes) are
pseudorandom up to $\varepsilon_{\mathrm{indiff}}$. This holds for both overwrite-mode absorption (used by leaves) and
standard XOR-mode absorption (used by TurboSHAKE128, including the final node).

*Proof.* The argument proceeds in three steps: an absorption-mode equivalence, a direct
ideal-permutation argument for pseudorandomness, and a supporting reference to MRV15.

1. **Absorption-mode equivalence.** Both overwrite and XOR-absorb modes yield the same
   $\varepsilon_{\mathrm{indiff}}$ bound. The standard sponge indifferentiability result (BDPVA07/08) covers XOR-absorb;
   BDPVA11 (Theorem 2) extends to overwrite mode. For overwrite-mode leaves, the encrypt operation
   $S[j] \leftarrow \mathit{pt}[j] \oplus S[j] = \mathit{ct}[j]$ is algebraically identical to XOR-absorbing the
   plaintext, so the distinction is moot.

2. **Direct ideal-permutation argument.** Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$, rate outputs are
   pseudorandom by a direct argument from the definition of an ideal permutation:
   - The init step absorbs the truly random key $K_{tw}$ into the rate and applies $\pi$. The rate — containing the
     random key material — makes this first permutation input unique. The output capacity is therefore uniform.
   - $\neg\mathsf{Bad}_{\mathrm{perm}}$ guarantees that every subsequent capacity state is unique across all
     $\pi$-calls. Since the capacity occupies a fixed 256-bit subset of the 1600-bit state, distinct capacity portions
     imply distinct full inputs, regardless of rate content.
   - An ideal permutation applied to a fresh input produces a uniformly random 1600-bit output.
   - Therefore all rate outputs (keystream bytes and terminal squeeze bytes) are uniformly random.

3. **Supporting reference (MRV15).** Mennink-Reyhanitabar-Vizar (Eurocrypt 2015) independently confirm the same
   $(\sigma + t)^2 / 2^{c+1}$ bound for the keyed duplex via a more general framework.

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

This bijection is used in Section 6.8 (CMT-4) to rule out two different plaintexts opening the same ciphertext under
one key.

**Consequence.**
By Lemma 3 (fixed-key bijection), distinct plaintexts produce distinct ciphertexts under a fixed key, so the tag can be
viewed equivalently as a function of plaintext or ciphertext. Tag pseudorandomness is established separately in Section 6.4.

> **Remark** (ideal permutation sampling). In the ideal permutation model, outputs are sampled without replacement
> (permutation, not function). This introduces a negligible PRP/PRF distinction (standard PRP/PRF switching lemma):
> after $k$ queries, the next output is uniform over $2^{1600} - k$ values rather than $2^{1600}$, giving a statistical
> distance of at most $\sigma^2 / 2^{1601}$ from truly independent uniform outputs. This term is asymptotically
> swallowed by $\varepsilon_{\mathrm{indiff}} = (\sigma+t)^2/2^{c+1}$ (since $c = 256 \ll 1600$). Wherever the
> analysis claims "uniform" or "independent" outputs from the ideal permutation on distinct inputs, the PRP/PRF
> switching cost is implicitly absorbed into the dominant $\varepsilon_{\mathrm{indiff}}$ term.

### 6.4 Tag Security

This section establishes that the tag output is pseudorandom and collision-resistant under a uniformly random key.
Section 6.4.1 establishes tag PRF security; Section 6.4.2 establishes tag collision resistance. The
$n = 1$ and $n > 1$ paths are structurally parallel: both are keyed sponge instances with distinct indices
(Section 5). They are analyzed separately below, but the bound is the same in both cases.

#### 6.4.1 Tag PRF Security

**Case $n = 1$.** The tag is `single_node_tag()`: a direct squeeze from the leaf's overwrite-mode keyed sponge (index 1)
with domain byte 0x61 (see Section 5 for the construction). By Lemma 1 (applied with preconditions: the leaf is an
overwrite-mode keyed sponge initialized with a uniformly random key, operating in the ideal-permutation model), this
output is pseudorandom up to $\varepsilon_{\mathrm{indiff}}$.

**Case $n > 1$.** The final node is a keyed sponge: it is a TurboSHAKE128 call whose input begins with
$K_{tw} \| \mathrm{LEU64}(0)$ (see Section 5, final-node computation). Leaves use indices 1 through $n$; the final
node uses index 0. All init inputs are therefore distinct.

By Lemma 1 (generalized to XOR-absorb mode), the final node's rate outputs are pseudorandom up to
$\varepsilon_{\mathrm{indiff}}$. Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, every $\pi$-call (across all $n$ leaves
and the final node) has a unique capacity input. The final node only needs its own capacity states to be fresh, which
is guaranteed by $\neg\mathsf{Bad}_{\mathrm{perm}}$.

The tag is a squeeze from this keyed sponge — pseudorandom by Lemma 1. No additional $\varepsilon_{\mathrm{indiff}}$
charge is incurred beyond the global charge in Section 6.2, because $\sigma + t$ already counts the final-node
permutation calls.

Combining both cases:

$$
\varepsilon_{\mathrm{prf}} \le \varepsilon_{\mathrm{indiff}}.
$$

#### 6.4.2 Tag Collision Resistance

For $Q$ AEAD outputs (each a ciphertext-tag pair, as defined in Section 6.1) under one fixed secret key:

$$
\varepsilon_{\mathrm{coll}} \le \varepsilon_{\mathrm{indiff}} + \frac{Q^2}{2^{8\tau+1}}.
$$

Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$, tags are pseudorandom $\tau$-byte outputs (Section 6.4.1). The
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
independent uniform outputs (the PRP/PRF switching distance $\leq \sigma^2/2^{1601}$ is negligible compared to
$\varepsilon_{\mathrm{indiff}}$; see the Remark before Section 6.4).

Combining both cases: for any pair of distinct AEAD outputs $(i, j)$ (whether within-key or cross-key),
$\Pr[T_i = T_j] \leq 2^{-8\tau} + \delta_{\mathrm{pair}}$ where
$\delta_{\mathrm{pair}} \leq \sigma^2/2^{1601}$ (PRP/PRF switching, absorbed by $\varepsilon_{\mathrm{indiff}}$).
The birthday bound over all $\binom{Q}{2}$ pairs then gives the $Q^2/2^{8\tau+1}$ term.

### 6.5 IND-CPA (Nonce-Respecting)

By the bridge theorem (Section 6.2), it suffices to bound
$\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}}$ -- the IND-CPA advantage of the internal functions under
independent uniformly random per-context keys.

**Claim.** Within $\mathsf{G}_1$ conditioned on
$\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$, the IND-CPA advantage of the internal functions is
exactly zero: $\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} = 0$. The unconditional real-world bound is
$\varepsilon_{\mathrm{indiff}} + \varepsilon_{\mathrm{ctx\text{-}coll}}$.

*Justification.* In $\mathsf{G}_1$ conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$:

- Each encryption query uses a fresh nonce (nonce-respecting), so each context string $X$ is distinct.
- Distinct contexts map to independent uniformly random keys in $\mathsf{G}_1$.
- Under a truly random key $K_{tw}$ (from the lazy RF in $\mathsf{G}_1$) and the ideal permutation conditioned on
  $\neg\mathsf{Bad}_{\mathrm{perm}}$, the ciphertext distribution is independent of the adversary's plaintext choice.
  The argument proceeds by induction over rate blocks, showing that each ciphertext block is uniformly distributed
  regardless of the plaintext:
  - *Block 0:* The `init` step absorbed the truly random key $K_{tw}$ and applied $\pi$ via `pad_permute` (one
    permutation call); the resulting state is uniformly random (see Lemma 1, step 2). The first rate block of
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

The adversary therefore receives uniformly random ciphertexts regardless of which plaintext it submits, giving zero
distinguishing advantage within this conditioned game.

Therefore:

$$
\varepsilon_{\mathrm{ind\text{-}cpa}} \le \varepsilon_{\mathrm{indiff}} + \varepsilon_{\mathrm{ctx\text{-}coll}}.
$$

### 6.6 INT-CTXT

**Claim.** $\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}.$

*Justification.* In $\mathsf{G}_1$ conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$, each
forgery attempt targets a context with a uniformly random key. The tag is a pseudorandom $\tau$-byte value (by
Lemma 1 and Section 6.4.1). Each forgery attempt — i.e., a (ciphertext, tag) pair not previously output by the
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
\varepsilon_{\mathrm{int\text{-}ctxt}} \le \varepsilon_{\mathrm{indiff}} + \frac{S}{2^{8\tau}} + \varepsilon_{\mathrm{ctx\text{-}coll}}.
$$

If tags are truncated to $T<\tau$ bytes, replace $S/2^{8\tau}$ with $S/2^{8T}$.

### 6.7 IND-CCA2 (Nonce-Respecting)

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

**Step 2: Substitute bare bounds.** From Sections 6.5 and 6.6:
$\mathrm{Adv}_{\mathrm{IND\text{-}CPA}}^{\mathrm{bare}} = 0$ and
$\mathrm{Adv}_{\mathrm{INT\text{-}CTXT}}^{\mathrm{bare}} \le S / 2^{8\tau}$. Therefore:

$$
\mathrm{Adv}_{\mathrm{IND\text{-}CCA2}}^{\mathrm{bare}} \le \frac{S}{2^{8\tau}}.
$$

**Step 3: Lift through bridge theorem.** Applying the decomposition from Section 6.2:

$$
\varepsilon_{\mathrm{ind\text{-}cca2}} \le \varepsilon_{\mathrm{indiff}} + \frac{S}{2^{8\tau}} + \varepsilon_{\mathrm{ctx\text{-}coll}}.
$$

> *Note on construction type.* TreeWrap128 is structurally an encrypt-and-MAC scheme (the tag is derived from the
> same sponge state as the ciphertext), not an Encrypt-then-MAC scheme with independent keys. The BN00 composition
> theorem (Theorem 4.3) is a general result: it states that *any* symmetric encryption scheme satisfying both IND-CPA
> and INT-CTXT also satisfies IND-CCA2. The theorem's only preconditions are these two properties of the composed
> scheme, not any requirement on its internal structure (e.g., independent keys or separate MAC). Sections 6.5 and 6.6
> establish IND-CPA and INT-CTXT for TreeWrap128 directly, so the theorem applies. The overwrite-mode sponge ensures
> that the tag depends on the ciphertext (ciphertext bytes are written into the rate before the tag squeeze), which is
> why INT-CTXT holds despite the shared state.

Nonce reuse for the same $(K,N,AD)$ is out of scope for this claim and breaks standard nonce-respecting
IND-CCA2 formulations.

### 6.8 CMT-4 (Fixed Master Key)

This theorem follows the standard Bellare-Hoang committing-security notion (CMT-4, see Section 8): a ciphertext should not
admit two distinct valid openings under one fixed secret key. The proof is a composition argument over Section 6.2 plus
fixed-key injectivity of the internal functions (Lemma 3).

**Game (CMT-4, nonce-respecting).** Sample one secret master key $K$ once and give the adversary encryption-oracle
access under $K$ with nonce-respecting queries. The adversary outputs one ciphertext $C^\star$ and two distinct opening
tuples $(N,AD,M) \neq (N',AD',M')$ with $|M| = |M'| = |C^\star| - \tau$ (enforced by the ciphertext length). It wins iff both openings verify:

$$
\mathrm{Dec}(K,N,AD,C^\star)=M \quad\text{and}\quad \mathrm{Dec}(K,N',AD',C^\star)=M'.
$$

As in Section 6.5, move to $\mathsf{G}_1$ where context-to-key derivation is replaced by a lazy random function and pay one
global $\varepsilon_{\mathrm{indiff}}$ term for $\mathsf{Bad}_{\mathrm{perm}}$.

Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}} \wedge \neg\mathsf{CtxColl}$:

- **Case 1: same context** $(N,AD)=(N',AD')$. Both openings use the same derived key. Since
  $(N,AD,M) \neq (N',AD',M')$ and the contexts are equal, we must have $M \neq M'$. Because the ciphertext $C^\star$
  fixes the plaintext length ($|M| = |M'| = |C^\star|$ minus the tag), both messages have identical chunking. Then two
  different messages opening the same $C^\star$ under the same key and chunking contradict Lemma 3 (fixed-key
  bijection), so this case is impossible.
- **Case 2: different contexts** $(N,AD)\neq(N',AD')$. Contexts map to distinct random keys in $\mathsf{G}_1$. A dual
  valid opening then requires that the same ciphertext decrypts validly under two different derived keys, which means
  the $\tau$-byte tags must match across the two tag computations. Different derived keys produce different init
  absorptions, hence different capacity states after the first permutation call. With
  $\neg\mathsf{Bad}_{\mathrm{perm}}$ covering all $\pi$-call pairs globally (including cross-context pairs), the two
  tag computations query $\pi$ on disjoint inputs. The ideal permutation on disjoint inputs produces approximately
  independent uniform outputs (up to PRP/PRF switching distance $\leq \sigma^2/2^{1601}$, absorbed by
  $\varepsilon_{\mathrm{indiff}}$). For $n > 1$: different keys produce different first permutation inputs across all
  leaves and final nodes. Under $\neg\mathsf{Bad}_{\mathrm{perm}}$, no capacity collision occurs between any pair of
  calls from the two contexts, so by Lemma 1 the two final-node tags are approximately independent uniform $\tau$-byte
  strings. The probability that two approximately independent uniform $\tau$-byte tags collide is upper-bounded by the
  $Q$-comparison birthday term.

Therefore:

$$
\varepsilon_{\mathrm{cmt4}} \le \varepsilon_{\mathrm{indiff}} + \frac{Q^2}{2^{8\tau+1}} + \varepsilon_{\mathrm{ctx\text{-}coll}}.
$$

Here $Q$ (as defined in Section 6.1) counts all AEAD outputs in the experiment: encryption-oracle responses plus the two
openings in $C^\star$. The adversary can choose $C^\star$ to exploit a cross-context tag collision among any pair of
these $Q$ outputs, so the birthday bound $Q^2/2^{8\tau+1}$ applies rather than a single targeted-forgery bound of
$1/2^{8\tau}$.

For $\tau = C = 32$, both birthday denominators are $2^{257}$.

### 6.9 Bare Usage (EncryptAndMAC / DecryptAndMAC)

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
| CMT-4                        | Provide external key derivation with collision resistance over injectively encoded AEAD contexts. |

### 6.10 Chunk Reordering, Length Changes, and Empty Input

- Reordering chunks changes leaf-index binding (`key || LEU64(index)`), so recomputed tag changes.
- Truncation/extension changes chunk count $n$, changing `length_encode(n)` in final accumulation input.
- Empty plaintext uses $n=1$: one leaf with `single_node_tag()`, no final accumulation node.

### 6.11 Side Channels

Implementations MUST be constant-time with respect to secret-dependent control flow and memory access.

- No lookup tables indexed by secret state bytes.
- Tag verification MUST use constant-time equality.
- Partial-block logic may branch on public length, not on secret data.

### 6.12 Operational Usage Limits (Normative)

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

### 6.13 Implementation Design Callouts (Non-Normative)

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
- **Keep domain bytes and index mapping exact.** `0x60`-`0x64` constants and `key || LEU64(index)` binding (index 0
  for the final node, indices 1..$n$ for leaves) are structural for interoperability and security analysis.
- **Treat reference code as correctness-first.** For production throughput, avoid repeated byte-string concatenation
  patterns when constructing final-node inputs.

## 7. Comparison with Traditional AEAD

TreeWrap128 differs from traditional AEAD in several respects.

**Nonce-free internal primitive.** The internal encrypt-and-MAC functions take only a key and data. Nonces are consumed
by the TurboSHAKE128-based KDF to derive a unique internal key, not passed to the encrypt/MAC layer itself.

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs -- they prove authenticity but are not
necessarily pseudorandom. TreeWrap128's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (Section 6.4.1). This stronger property is useful for protocols that derive further keying material from the tag.

### 7.1. Operational Safety Limits

Operational planning assumptions used in this section: $p = 2^{-50}$, 1500-byte messages, TreeWrap128 cost
$\approx 11$ Keccak-p calls/message (1 KDF + 10 leaf calls), and per-key accounting (single key / key epoch). Figures
are conditional on the Section 6 model assumptions for Keccak-p[1600,12] and the selected offline-work profile.

Under those assumptions, the TreeWrap128 proof-bound-only volume is approximately $2^{80.6}$ GiB per key epoch. This is an
analytical upper bound, not the practical deployment limit when random nonces are used.

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
| 256-bit    | 1500 B      | proof bound      | $\approx 2^{80.6}$ GiB           |

For a different record size, scale the nonce-collision-limited rows linearly with bytes/record and then apply the same
minimum rule against the proof-bound volume.

Configured usage limits SHOULD be driven by nonce policy and key-epoch rotation controls (Section 6.12), not by the asymptotic
proof-bound figure alone.

## 8. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007. Establishes
  the flat sponge claim (sponge indifferentiability from a random oracle).
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
  CRYPTO 2005. Applies the MRH indifferentiability composition theorem to hash function constructions; used in Section
  6.2 for the KDF game hop.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.
- Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the Generic
  Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2; used in Section 6.7.
- Namprempre, C., Rogaway, P., and Shrimpton, T. "Reconsidering Generic Composition." EUROCRYPT 2014. Extends the
  BN00 composition theorem to the nonce-based setting; used in Section 6.7.
- Ristenpart, T., Shacham, H., and Shrimpton, T. "Careful with Composition: Limitations of the Indifferentiability
  Framework." Eurocrypt 2011 (ePrint 2011/339 as "Limitations of Indifferentiability and Universal Composability").
  Highlights multi-stage composition caveats; motivates explicit game-hop arguments in composed proofs.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass Authenticated Encryption
  and Other Applications." SAC 2011. IACR ePrint 2011/499. Proves that duplex outputs are pseudorandom under the sponge
  indifferentiability assumption (Theorem 1) and gives overwrite-mode security (Section 6.2, Algorithm 5, Theorem 2:
  Overwrite is as secure as Sponge); establishes that all intermediate rate outputs -- not just terminal squeezes -- are
  covered by the duplex security bound.
- Mennink, B., Reyhanitabar, R., and Vizar, D. "Security of Full-State Keyed Sponge and Duplex: Beyond the Birthday
  Bound." Eurocrypt 2015. Provides direct ideal-permutation-model bounds for the keyed duplex, giving a tighter
  reduction than routing through sponge indifferentiability.
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

## 9. Test Vectors

### 9.1 Internal Function Vectors

All internal function vectors use:

- **Key:** 32 bytes `00 01 02 ... 1f`
- **Plaintext:** `len` bytes `00 01 02 ... (len-1) mod 256`

Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.

#### 9.1.1 Empty Plaintext (MAC-only, n = 1)

| Field | Value |
|-------|-------|
| len | 0 |
| ct | (empty) |
| tag | `04de4572bd86958d645b9a72d843546cad974b41e7d9e0ae45fb0a03cd6d6a06` |

#### 9.1.2 One-Byte Plaintext (n = 1)

| Field | Value |
|-------|-------|
| len | 1 |
| ct | `6e` |
| tag | `d93a5f718170bfe41a8ce01c590b555038f233f0e6eae4ab9d131ca43f303177` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`d26a3af83e224becc63a2fe87aa53b2d012dbbba2cda81d77ba5a7e0fcddcdc6`.

#### 9.1.3 B-Byte Plaintext (exactly one chunk, n = 1)

| Field | Value |
|-------|-------|
| len | 8192 |
| ct[:32] | `6e9bbe6b49e800fbb150f445717678c39ca857d33d382980dc023e2d64134f1d` |
| tag | `d72bc680d344ae9cbd6f08cc18e3a164f9427672bcce67c673734978c8562bb8` |

Flipping bit 0 of `ct[0]` yields tag
`cd1fce6f02bd91b1e3a78f4345c04ebdad01138f239791a7f29741c3c36551e9`.

#### 9.1.4 B+1-Byte Plaintext (two chunks, minimal second, n = 2)

| Field | Value |
|-------|-------|
| len | 8193 |
| ct[:32] | `6e9bbe6b49e800fbb150f445717678c39ca857d33d382980dc023e2d64134f1d` |
| tag | `3aea66ff9e65ce5cd25552c9df5311be173077fe1f0b9a84b562960734dcc122` |

Flipping bit 0 of `ct[0]` yields tag
`6d0507b040b49707d3e7c71589eb69c5edfb2b072fe0fa0626a17d308d3a44f0`.

#### 9.1.5 4B-Byte Plaintext (four full chunks, n = 4)

| Field | Value |
|-------|-------|
| len | 32768 |
| ct[:32] | `6e9bbe6b49e800fbb150f445717678c39ca857d33d382980dc023e2d64134f1d` |
| tag | `db63c80b11de51dd981d0742d59ecebd3d2e60ed6e749352fd9c4e6ebe649dfc` |

Flipping bit 0 of `ct[0]` yields tag
`cf955beeba9af9af732fb9f4fc8f20165946e8b2ad511be4d42df8550f4d05c8`.

Swapping chunks 0 and 1 (bytes 0-8,191 and 8,192-16,383) yields tag
`56fc09804c815bc4b1fa8c9fc2f7079907f6783d23f59342677a9b5575393b1f`.

#### 9.1.6 Round-Trip Consistency

For all internal function vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as
`EncryptAndMAC`.

### 9.2 TreeWrap128 Vectors

These vectors validate `treewrap128_encrypt` / `treewrap128_decrypt`, including SP 800-185
`encode_string` key derivation.

#### 9.2.1 Empty Message

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | (empty) |
| M len | 0 |
| ct‖tag | `a6c901956a827e238fbad29bd3a59897e019c59d6f235281de634a348dd78e37` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.2.2 33-Byte Message With 5-Byte AD

| Field | Value |
|-------|-------|
| K | 32 bytes `00 01 02 ... 1f` |
| N | 12 bytes `a0 a1 a2 ... ab` |
| AD | 10 11 12 ... 14 |
| M len | 33 (`00 01 02 ... mod 256`) |
| ct‖tag | `0e9f8e659d83af141bdc10090b82c9434e14041f673ed47fd55008b981994d8ce720aff7a9b931c5c791abefb5b8c21c8835894a755ee96b02460bf21adb217ece` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.2.3 Multi-Chunk Message (8193 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `42 43 44 ... 61` |
| N | 12 bytes `c0 c1 c2 ... cb` |
| AD | 00 01 02 ... 10 |
| M len | 8193 (`00 01 02 ... mod 256`) |
| ct[:32] | `cf08993957d501bb9108582fb2d982b1daf037f1b6d35e5f8a3e3a964729f638` |
| tag | `4ac4bf58d2b3db7808f284c09a92bc6fd7773df7c8e2c83b78982c148f9003eb` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

#### 9.2.4 Nonce Reuse Behavior (Equal-Length Messages)

| Field | Value |
|-------|-------|
| K | 32 bytes `00 11 22 ... ff` |
| N | 12 bytes `ff ee dd cc bb aa 99 88 77 66 55 44` |
| AD | a1 a2 a3 ... a4 |
| M len | 64 (`00 01 02 ... mod 256`) |
| ct‖tag | `96f62aaccce146a77573c0441b4e671ed044790fad22a782b122b4763f989ac8663a3cbf8f5743dcd5501b3d1f1d556ead47e18d2cfe9404b4fb286a1b63f3cd36c5cd65fe010dcd5680efe55a6032d4f9a6c489584a3ee970ea65b7e7f72f05` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Reusing the same `(K, N, AD)` with a different message is deterministic and yields
`ct1 xor ct2 = m1 xor m2` for equal-length messages (validated by this vector).
Nonce reuse is out of scope for Section 6 nonce-respecting claims.

#### 9.2.5 Swapped Nonce and AD Domains

| Field | Value |
|-------|-------|
| K | 32 bytes `0f 0e 0d ... 00` |
| N | 12 bytes `00 01 02 ... 0b` |
| AD | 10 11 12 ... 1b |
| M len | 48 (`00 01 02 ... mod 256`) |
| ct‖tag | `c07af2f0ce3b4eb1f1bc9914964ee498c0481bf1dff4bb61ab82adbf63c834dcb5e02d326e5e2949d7847628ea52bf48e2ebf9f61e9577701ee1ec33c1d50ab7efbc3343ddb9a571abee12e49a112ff6` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Swapping `N` and `AD` (same byte length) yields a different `ct‖tag` and does not
validate the original `ct‖tag`.

#### 9.2.6 Empty AD vs One-Byte AD 00

| Field | Value |
|-------|-------|
| K | 32 bytes `88 99 aa ... ff` |
| N | 12 bytes `0c 0d 0e ... 17` |
| AD | (empty) |
| M len | 32 (`00 01 02 ... 1f`) |
| ct‖tag | `3dfb7d84090da44235e96f8308af5a8d043ff9883d21feefd7f8b3115bb74ee4267411ec2b655cfe0131f7c897d3adedec478891a197add10a68d21137592ec3` |

`treewrap128_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.
Empty AD and one-byte AD `00` are distinct contexts and produce different `ct‖tag`.

#### 9.2.7 Long AD (128 Bytes)

| Field | Value |
|-------|-------|
| K | 32 bytes `10 21 32 ... ff` |
| N | 12 bytes `ab ab ac ad ae af b0 b1 b2 b3 b4 b5` |
| AD | ab ab ab ... ab |
| M len | 17 (`00 01 02 ... 10`) |
| ct‖tag | `7806d66b3e4c5a6ec2131f9735e281cdb7c6562dcb4de65566a730cec715e110b763e4ecd72b74f68c15cc32f39384030b` |

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

The security bounds in Section 6 are driven by the total Keccak-p call budget term:

$$
\varepsilon_{\mathrm{indiff}} = \frac{(\sigma + t)^2}{2^{c+1}}.
$$

When a deployment uses multiple Keccak-based components under related security assumptions, a conservative practice is
to budget their Keccak-p calls together rather than treating each component in isolation.

### C.2 Practitioner workflow

For a chosen operational window (for example, per key epoch, per process lifetime, or per day), define:

```text
sigma_total = sigma_treewrap128 + sigma_turboshake + sigma_k12 + sigma_other_keccak
```

where each term is the count of online Keccak-p[1600,12] calls made by that component in the window.
This is the same $\sigma_{\mathrm{total}}$ counter model used normatively in Section 6.12.

Then evaluate:

$$
\varepsilon_{\mathrm{budget}} = \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}}
$$

for your selected adversary offline budget $t$.

Use this as a planning control:

- if $\varepsilon_{\mathrm{budget}}$ is below your target risk threshold, the window budget is acceptable;
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
