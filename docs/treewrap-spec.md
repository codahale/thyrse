# TreeWrap: Tree-Parallel Stream Cipher and MAC

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.7</td></tr>
  <tr><th>Date</th><td>2026-03-01</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

TreeWrap is a deterministic stream cipher with a MAC tag, using a Sakura flat-tree topology to enable SIMD acceleration
(NEON, AVX2, AVX-512) on large inputs. Each leaf encrypts by XORing plaintext with the Keccak sponge state and writing
the ciphertext back into the rate, and leaf chain values are accumulated into a single MAC tag via TurboSHAKE128.

TreeWrap is not an AEAD scheme. It does not perform tag verification internally. Instead, it exposes two
operations—**`EncryptAndMAC`** and **`DecryptAndMAC`**—which both return the computed tag to the caller. The caller is
responsible for tag comparison, transmission, and any policy decisions around verification failure. This design supports
protocol frameworks like Thyrse that need to absorb the tag into an ongoing state regardless of verification outcome, or
that authenticate ciphertext through external mechanisms such as signatures.

TreeWrap is a pure function with no internal state. The caller manages key uniqueness and associated data.

## 2. Parameters

| Symbol | Value             | Description                                           |
|--------|-------------------|-------------------------------------------------------|
| f      | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds)    |
| R      | 168               | Sponge rate (bytes); data rate is R−1 = 167 per block |
| C      | 32                | Capacity (bytes); key and chain value size            |
| τ      | 32                | Tag size (bytes); equal to C for this instantiation   |
| B      | 8192              | Chunk size (bytes), matching KangarooTwelve           |

**Parameter constraints.** $C + 8 \leq R - 1$ (init material `key ‖ [index]₆₄LE` = $C + 8 = 40$ bytes fits in a
single rate block). $\max(\tau, C) < R$ (tag and chain value outputs fit in a single squeeze block).

## 3. Dependencies

**`TurboSHAKE128(M, D, ℓ)`:** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D`
(0x01 – 0x7F), and an output length `ℓ` in bytes.

## 4. Leaf Cipher

A leaf cipher operates on a standard Keccak sponge with the same permutation and rate/capacity parameters as
TurboSHAKE128. It uses six domain separation bytes, reserved for TreeWrap:

| Byte   | Usage                        | Procedure(s)             |
|--------|------------------------------|--------------------------|
| `0x60` | Init (key/index absorption)  | `init`                   |
| `0x61` | Single-node tag squeeze      | `single_node_tag`        |
| `0x62` | Intermediate encrypt/decrypt | `encrypt`, `decrypt`     |
| `0x63` | Final block (chain value)    | `chain_value`            |
| `0x64` | Tag accumulation             | `TreeWrap`, `TreeUnwrap` |
| `0x65` | AEAD key derivation          | `TreeWrap-AEAD`          |

> [!NOTE]
> **System-wide permutation accounting.** All Keccak-p[1600,12] evaluations across the entire system — by TreeWrap,
> by other components using TurboSHAKE128 or any Keccak-based primitive, and by the adversary — contribute to the
> total budget $\sigma + t$ in the security bounds (§6.2). For example, a system using both TreeWrap and
> KangarooTwelve simply sums the permutation calls from both when evaluating the security margin. In practice this
> is not a concern: encrypting or hashing one terabyte of data costs approximately $2^{33}$ permutation calls, so
> even an aggressive workload of $2^{50}$ total calls across all components leaves the security margin at
> $(2^{50})^2 / 2^{257} = 2^{-157}$ — far below any practical threshold.

Unlike the XOR-absorb approach used by SpongeWrap, the `encrypt` and `decrypt` operations write ciphertext directly
into the rate rather than XORing plaintext into it. This enables a clean security reduction to the standard Keccak
sponge via a per-byte algebraic identity (§6.12, Step 1), and for full-rate blocks, a write-only state update is faster
than read-XOR-write on most architectures.

The leaf cipher is defined by the following reference implementation. `keccak_p1600` and `turboshake128` are
defined in Appendix B.

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
        for j, p in enumerate(plaintext):
            ct.append(p ^ self.S[self.pos])
            self.S[self.pos] = ct[-1]
            self.pos += 1
            if self.pos == R - 1 and j < len(plaintext) - 1:
                self.pad_permute(0x62)
        return bytes(ct)

    def decrypt(self, ciphertext: bytes) -> bytes:
        pt = bytearray()
        for j, c in enumerate(ciphertext):
            pt.append(c ^ self.S[self.pos])
            self.S[self.pos] = c
            self.pos += 1
            if self.pos == R - 1 and j < len(ciphertext) - 1:
                self.pad_permute(0x62)
        return bytes(pt)

    def single_node_tag(self) -> bytes:
        self.pad_permute(0x61)
        return bytes(self.S[:TAU])

    def chain_value(self) -> bytes:
        self.pad_permute(0x63)
        return bytes(self.S[:C])
```

**Notes.** `pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at `R-1`). `init`
uses domain byte `0x60`, distinct from the intermediate byte `0x62`, ensuring key absorption is
domain-separated from ciphertext blocks. Both `encrypt` and `decrypt` overwrite the rate with ciphertext,
so state evolution is identical regardless of direction. `single_node_tag` and `chain_value` begin with
`pad_permute` to mix all data before squeezing; both outputs fit in a single squeeze block since
$\max(\tau, C) = 32 \ll R = 168$.

## 5. TreeWrap

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.

The NIST SP 800-185 encodings (`left_encode`, `right_encode`, `encode_string`) are defined as Python functions
in Appendix B.

### 5.1 EncryptAndMAC / DecryptAndMAC

**`TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)`**\
**`TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)`**

*Inputs:*

- `key`: A C-byte key. MUST be pseudorandom (computationally indistinguishable from uniform — required for the PRF
  reductions in §6.3–§6.7) and unique per invocation (no two calls share a key — required for fresh-input
  guarantees). See §6.1 and §6.2.
- `plaintext` / `ciphertext`: Data of any length (may be empty). Maximum length is $(2^{64} - 1) \cdot B$ bytes,
  since leaf indices are encoded as 8-byte little-endian integers.

*Outputs:*

- `ciphertext` / `plaintext`: Same length as the input data. Length reveals plaintext length; the chunking structure
  ($n$, $\ell_0, \ldots, \ell_{n-1}$) is public. Protocols requiring length hiding must pad before calling TreeWrap.
- `tag`: A τ-byte MAC tag.

*Procedure:*

```python
def _tree_process(key: bytes, data: bytes, direction: str) -> tuple[bytes, bytes]:
    """Shared logic for EncryptAndMAC / DecryptAndMAC."""
    n = max(1, -(-len(data) // B))
    chunks = [data[i * B : (i + 1) * B] for i in range(n)]

    if n == 1:
        L = LeafCipher()
        L.init(key, 0)
        out = L.encrypt(chunks[0]) if direction == "E" else L.decrypt(chunks[0])
        return out, L.single_node_tag()

    out_parts, cvs = [], []
    for i, chunk in enumerate(chunks):
        L = LeafCipher()
        L.init(key, i)
        out_parts.append(L.encrypt(chunk) if direction == "E" else L.decrypt(chunk))
        cvs.append(L.chain_value())

    final_input = bytes([0x03, 0, 0, 0, 0, 0, 0, 0])
    for cv in cvs:
        final_input += cv
    final_input += right_encode(n)
    final_input += b"\xff\xff"
    tag = turboshake128(final_input, 0x64, TAU)
    return b"".join(out_parts), tag

def encrypt_and_mac(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, plaintext, "E")

def decrypt_and_mac(key: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    return _tree_process(key, ciphertext, "D")
```

All leaf operations are independent and may execute in parallel. Tag computation begins as soon as all chain values are
available. `decrypt_and_mac` produces the same tag as `encrypt_and_mac` because both `encrypt` and `decrypt`
write ciphertext into the sponge rate (§4). The caller is responsible for comparing the returned tag against an
expected value; TreeWrap does not perform tag verification.

### 5.3 TreeWrap-AEAD

TreeWrap-AEAD is a concrete AEAD construction built on top of the bare TreeWrap primitive. It derives a per-invocation
TreeWrap key from `(K, N, AD)` using TurboSHAKE128, then delegates to `EncryptAndMAC`/`DecryptAndMAC`. This
construction exists for security analysis — calling protocols may use it directly or implement equivalent key
derivation.

**Key derivation:**

```
tw_key ← TurboSHAKE128(encode_string(K) ‖ encode_string(N) ‖ encode_string(AD), 0x65, C)
```

The `encode_string` encoding (§5, NIST SP 800-185) makes the concatenation injective: each field is prefixed
with its `left_encode`d length, so no `(K, N, AD)` triple can produce the same TurboSHAKE128 input as a
different triple.
Domain byte `0x65` separates key derivation from all other TreeWrap uses of TurboSHAKE128 (`0x60`–`0x64`).

```python
def treewrap_aead_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x65, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap_aead_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x65, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if tag == tag_expected else None
```

## 6. Security Properties

TreeWrap provides the following security properties under the assumptions stated below. The formal security reductions
model the underlying Keccak-p[1600,12] permutation as a random permutation. In reality, 12-round Keccak is known to have
permutation-level distinguishers (e.g., zero-sum distinguishers) and is therefore not perfectly indistinguishable from
random. However, TreeWrap relies on the same heuristic assumption as KangarooTwelve and TurboSHAKE: that these
permutation-level properties do not translate into structural breaks of the sponge construction, and that the sponge
indifferentiability claim holds up to the 128-bit target security level. No duplex-specific attacks on reduced-round
Keccak are known to improve on generic sponge distinguishers, so the margin analysis for TurboSHAKE applies unchanged.
Each property reduces to the Keccak sponge claim via TurboSHAKE128's indifferentiability from a random oracle.
Leaf keystream pseudorandomness (needed for IND-CPA, §6.3) additionally reduces via the keyed duplex security
theorem (Bertoni et al. 2011; Mennink–Reyhanitabar–Vizár 2015), which itself reduces to sponge
indifferentiability — see §6.12 ("Keyed duplex interpretation") for the explicit correspondence.

### 6.1 AEAD Construction

To state standard security games (IND-CCA2, INT-CTXT, CMT-4), we use the concrete `TreeWrap-AEAD` construction
defined in §5.3. TreeWrap itself remains a bare `EncryptAndMAC`/`DecryptAndMAC` primitive; the AEAD wrapper
provides key derivation and tag verification for security analysis.

The KDF uses TurboSHAKE128 with domain byte `0x65` — the same Keccak-p permutation underlying all TreeWrap
operations. No separate KDF security assumption is needed: the sponge→RO reduction (§6.2) covers all
TurboSHAKE128 evaluations (including KDF evaluations) in a single hop. After the reduction, the injective
`encode_string` encoding (§5.3) ensures that distinct `(K, N, AD)` triples produce distinct random oracle inputs,
so each fresh nonce yields an independent, uniformly random `tw_key`.

The concrete KDF provides two properties used by the theorems below, both as immediate consequences of the
sponge→RO hop:

- **PRF security.** For uniform `K`, the mapping `(N, AD) → tw_key` is indistinguishable from a random function.
  Used by: IND-CPA (§6.3), INT-CTXT (§6.4), IND-CCA2 (§6.3.1).
- **Collision resistance.** Distinct `(K, N, AD) ≠ (K', N', AD')` (including adversary-chosen keys) produce
  distinct `tw_key` values in the RO world (injective encoding → distinct RO inputs). Used by: CMT-4 (§6.5).

> [!WARNING]
> **Key reuse.** Reusing `tw_key` compromises IND-CPA (leaks plaintext XOR differences within the first
> block) and weakens INT-CTXT within the first block. Unlike polynomial-MAC AEADs (e.g., AES-GCM), key reuse
> does not enable universal forgery — the sponge-based tag remains computationally unpredictable for novel
> ciphertexts. Callers MUST ensure key uniqueness (e.g., via the KDF in §5.3 with fresh nonces).

> [!NOTE]
> **Release of unverified plaintext (RUP).** The bare `DecryptAndMAC` interface is inherently malleable:
> flipping ciphertext bit $j$ in the first block flips plaintext bit $j$. This is a general property of stream
> ciphers under RUP, not specific to key reuse. Without key reuse the malleability is *blind* (the attacker
> cannot target specific values). Authentication depends entirely on the caller verifying the tag (see §6.5.1).

### 6.2 Security Model

**Random permutation model.** All bounds in this section model Keccak-p[1600,12] as a random permutation. This is a
heuristic assumption (see §6 preamble).

**Whole-system permutation budget.** The sponge indifferentiability theorem replaces all Keccak-p evaluations —
by TreeWrap, by other system components, and by the adversary — with random oracle evaluations in a single
reduction. The cost is $(\sigma + t)^2 / 2^{c+1}$, where $\sigma$ counts all online permutation calls across
the entire system and $t$ counts all offline (adversary) permutation calls. Other components using Keccak-p
(including TurboSHAKE128 on any domain byte) do not break the security reduction; they simply contribute to
$\sigma + t$. After the sponge-to-RO replacement, TreeWrap's security rests on the secrecy of `tw_key`: the
adversary cannot evaluate the keyed PRF without querying the random oracle on an input prefixed with the
256-bit key, regardless of what domain byte is used. Consequently, TreeWrap's domain byte separation (`0x60`–`0x65`)
is a proof convenience that simplifies the security argument, not a security requirement: if another Keccak-based
construction independently uses the same domain byte values, security is not broken — all evaluations simply
contribute to the shared $\sigma + t$ budget. See §4 for the corresponding implementer guidance.

**Notation:**

- $\sigma$: total online Keccak-p calls across all queries in the security game (KDF evaluations, all leaves,
  and tag computations combined, summed over all encryption and decryption queries). Each query contributes
  three components: the KDF evaluation ($\geq 1$ call), each leaf's init + encrypt/decrypt + squeeze ($\geq 2$
  calls per leaf), and the tag accumulation for multi-chunk messages ($\geq 1$ call when $n > 1$). Since even
  an empty message costs at least 3 Keccak-p calls (1 KDF + 2 leaf), $\sigma \geq 3Q$ for $Q$ queries. The
  exact formula is given in Appendix A. Representative per-query costs:

  | Message length $L$ | Chunks $n$ | $\sigma$ per query |
  |--------------------|------------|--------------------|
  | 0                  | 1          | 3                  |
  | 167 ($= R - 1$)    | 1          | 3                  |
  | 168 ($= R$)        | 1          | 4                  |
  | 8192 ($= B$)       | 1          | 52                 |
  | 16384 ($= 2B$)     | 2          | 104                |
- $t$: adversary's total offline Keccak-p calls.
- $c = 256$: capacity in bits.
- $C = 32$: capacity in bytes; key and chain value size.
- $\tau = 32$: tag size in bytes ($\tau = C$ for this instantiation).
- $S$: number of forgery attempts (§6.4) or verification queries.
- $Q$: number of distinct (key, ciphertext) pairs (§6.6) or encryption queries.

**Security convention.** The sponge indifferentiability advantage is $(\sigma + t)^2 / 2^{c+1}$. At adversarial
budget $\sigma + t = 2^{128}$, this evaluates to $2^{256} / 2^{257} = 2^{-1}$, i.e., constant advantage requires
$\approx 2^{128}$ work. "128-bit security" means $\approx 2^{128}$ work for constant advantage, following the
KangarooTwelve/TurboSHAKE convention. More generally, to achieve advantage $\leq 2^{-k}$, the adversarial budget
must satisfy $\sigma + t \leq 2^{(c+1-k)/2}$. For $c = 256$: advantage $\leq 2^{-1}$ at $\sigma + t = 2^{128}$,
or advantage $\leq 2^{-128}$ at $\sigma + t = 2^{64}$.

**Reading the bounds.** Every theorem in §6.3–§6.7 contains the sponge indifferentiability term
$(\sigma + t)^2 / 2^{c+1}$, which dominates all other terms at high query budgets. The following table translates
this term into concrete security levels for $c = 256$:

| Adversarial budget ($\sigma + t$) | Advantage upper bound | Interpretation                    |
|-----------------------------------|-----------------------|-----------------------------------|
| $2^{64}$                          | $2^{-128}$            | Negligible; cryptographic margin  |
| $2^{80}$                          | $2^{-96}$             | Conservative practical target     |
| $2^{128}$                         | $2^{-1}$              | Constant; theoretical break point |

Practitioners targeting a conventional "$n$-bit security" guarantee — meaning advantage $\leq 2^{-n}$ at some
specified work budget — should read the bounds with the formula $\sigma + t \leq 2^{(c+1-n)/2}$. For example,
achieving advantage $\leq 2^{-32}$ (a common practical target) requires $\sigma + t \leq 2^{112}$, which
comfortably accommodates any realistic workload. The additional terms in each theorem (tag guessing, key guessing)
are negligible relative to the sponge term at all practical budgets.

**Capacity vs. tag length.** The dominant term $(\sigma + t)^2 / 2^{c+1}$ caps overall security at $c/2 \approx 128$
bits of work for constant advantage, regardless of the tag length. The full 256-bit ($\tau = 32$) tag provides margin
against birthday-type terms (tag collisions at $Q^2 / 2^{8\tau+1}$) and key-guessing
($t / 2^{256}$), but does not raise the sponge ceiling. Readers should not infer "256-bit MAC security" from the
$\tau$-byte tag — the security level is determined by the capacity, not the tag length.

### 6.3 Confidentiality (IND-CPA)

*This property is stated for `TreeWrap-AEAD` (§5.3).*

**Game.** The adversary has access to an `Encrypt` oracle under a random key `K`. The oracle takes
$(N, \mathit{AD}, M_0, M_1)$ with $|M_0| = |M_1|$ and returns `Encrypt(K, N, AD, M_b)`. The adversary
is nonce-respecting: each encryption query uses a fresh `N`.

**Theorem.**

$$\varepsilon_{\mathrm{ind\text{-}cpa}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{t}{2^{256}}$$

where $\sigma + t$ is the total adversarial Keccak-p budget (notation defined in §6.2). The second term is
key guessing (see §6.7 for discussion); it is dominated by the sponge term for $\sigma + t \geq 2$.

**Proof sketch** (two game hops):

1. **Sponge → RO** (cost: $(\sigma + t)^2 / 2^{c+1}$). By the ciphertext-write to XOR equivalence (§6.12, Step 1), each
   leaf's interactive computation is expressible as a single standard sponge evaluation on an injective encoding
   of its inputs. The sponge indifferentiability theorem then replaces all such evaluations — across all leaves,
   the tag accumulation, and the KDF's TurboSHAKE128 evaluation (domain byte `0x65`) — with random oracle
   evaluations in a single reduction. The KDF evaluation is covered by the same hop because it is a standard
   TurboSHAKE128 call on the same Keccak-p permutation. Domain byte `0x65` ensures KDF inputs are disjoint from
   leaf cipher inputs (`0x60`–`0x63`) and tag accumulation inputs (`0x64`).

   After this hop, each fresh nonce yields an independent, uniformly random `tw_key`: the injective `encode_string`
   encoding (§5.3) ensures distinct `(K, N, AD)` triples produce distinct random oracle inputs, and the random
   oracle maps distinct inputs to independent uniform outputs. Output collisions occur with probability at most
   $Q^2 / 2^{257}$ (birthday bound on 256-bit outputs), which is dominated by the sponge term since
   $Q \leq \sigma$ (each query costs at least 3 Keccak-p calls; see §6.2).

2. **RO world.** After the rewriting in hop 1, each leaf is a random oracle evaluation with `tw_key` as a secret
   prefix. By construction, `tw_key` occupies the first 32 bytes of the equivalent sponge input (§6.12, Step 1),
   and the encoding is injective (§6.12, "Injectivity of the encoding"). Each leaf therefore defines a keyed PRF
   $F_K(i, P_i)$ where $K$ is the secret key prefix (§6.12, Step 2). In the RO world (after hop 1), the only
   remaining advantage is key guessing: the adversary must query the random oracle on an input prefixed with the
   secret 256-bit key, giving probability $t / 2^{256}$. The sponge indifferentiability term is already paid in
   hop 1.

   After the sponge→RO hop (hop 1), the rewritten leaf is a keyed duplex whose intermediate rate outputs — the
   keystream bytes XORed with plaintext — are pseudorandom by the duplex security theorem (Bertoni et al.,
   "Duplexing the Sponge," SAC 2011, Theorem 1). For tighter bounds in the keyed setting, Mennink–Reyhanitabar–Vizár
   (Eurocrypt 2015) provide direct ideal-permutation-model bounds for the full-state keyed duplex; the resulting
   advantage bound remains $(\sigma+t)^2/2^{c+1}$. See §6.12 ("Keyed duplex interpretation") for the explicit duplex
   correspondence. In the ideal world, each keystream byte $S[j]$ is therefore uniformly random before the
   corresponding ciphertext byte is produced. Therefore $\mathit{CT}_j = P_j \oplus S[j]$ where $S[j]$ is
   uniform, making $\mathit{CT}$ indistinguishable from uniform regardless of $P$.

   **No circularity (batch mode).** The equivalent sponge input for block $k$ contains the plaintext of block $k$,
   which is determined before the PRF output (keystream) for that block is produced. The PRF guarantee is that each
   output byte is uniform given only prior state, before the overwrite occurs. The resulting ciphertext is then
   overwritten into the state, but this feedback only affects subsequent blocks, not the current PRF evaluation.
   There is therefore no circular dependence between the PRF output and the plaintext appearing in its input.

   Crucially, TreeWrap is a batch primitive: the entire plaintext is provided at once before encryption begins, so
   the duplex inputs are fully determined before any output is produced. No adaptive-input extension of the duplex
   security theorem is needed — the standard non-adaptive formulation (Bertoni et al. 2011, Theorem 1) applies
   directly.

   For $n = 1$, the tag is squeezed from the leaf state with domain byte `0x61`, which is a direct PRF
   output under the secret key on a distinct domain. For $n > 1$, the tag is
   $\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x64}, \tau)$ — an unkeyed random oracle evaluated on a
   deterministic, injective encoding of the chain values. We argue tag pseudorandomness via a bad-event bound.
   Define event $B$: the adversary queries the random oracle on $\mathit{final\_input}$. Since
   $\mathit{final\_input}$ contains $n$ chain values, each a pseudorandom $8C$-bit PRF output under the secret
   key, and the adversary makes at most $t$ random oracle queries, $\Pr[B] \leq t / 2^{8Cn}$. Conditioned on
   $\lnot B$, the random oracle has not been evaluated at $\mathit{final\_input}$, so the tag is uniformly random
   and independent of the adversary's view. In both cases ($n = 1$ and $n > 1$),
   $(\mathit{CT}, \mathit{tag})$ is jointly indistinguishable from uniform. A fresh nonce
   implies a fresh `tw_key` (after hop 1), so each encryption query uses an independent key.

The key-guessing term $t / 2^{256}$ is stated explicitly in the bound for consistency with §6.7. Since
$t \leq \sigma + t$ implies $t / 2^{256} \leq (\sigma + t)^2 / 2^{c+1}$ for $\sigma + t \geq 2$, the
key-guessing term is dominated by the sponge term at all practical budgets.

### 6.3.1 CCA Security (IND-CCA2)

*This property is stated for `TreeWrap-AEAD` (§5.3).*

**Game.** The adversary has access to `Encrypt` and `Decrypt` oracles under a random key `K`. The `Encrypt` oracle
is as in §6.3; the adversary is nonce-respecting for encryption queries. The `Decrypt` oracle takes
$(N, \mathit{AD}, \mathit{CT} \| \mathit{tag})$ and returns `Decrypt(K, N, AD, CT ‖ tag)`; decryption queries may
reuse any nonce, including nonces used in encryption queries. The adversary may not submit a ciphertext returned by
`Encrypt` to `Decrypt` on the same `(N, AD)`.

IND-CCA2 security follows from the standard encrypt-then-MAC composition, applied after the single sponge→RO hop.

**Composition structure.** The encrypt-then-MAC composition requires two properties: (1) the tag is determined by the
key and ciphertext, and (2) encryption and tagging use independent keying material. TreeWrap satisfies both:

- **Encrypt-then-tag.** The tag is operationally determined by `(tw_key, ciphertext)`: given a key and ciphertext,
  `DecryptAndMAC` computes the tag without requiring the plaintext as a separate input. Although the equivalent sponge
  input (§6.12, Step 1) contains the plaintext (not the ciphertext), the encrypt bijection (§6.5 Case 2) ensures the
  tag is equivalently a PRF of the ciphertext (§6.12, Step 2).
- **Structural key separation.** After the sponge→RO hop, the KDF (domain byte `0x65`), leaf ciphers
  (`0x60`–`0x63`), and tag accumulation (`0x64`) operate on disjoint sets of random oracle inputs. Within a leaf,
  intermediate ciphertext blocks use domain byte `0x62`, while tag output uses `0x61` ($n = 1$) or `0x63`/`0x64`
  ($n > 1$). In the RO world, outputs on disjoint input domains are jointly independent: the adversary's
  view of domain-`0x62` outputs (keystream) is statistically independent of domain-`0x61`/`0x63`/`0x64`
  outputs (tags). The encryption keystream and the tag are therefore jointly pseudorandom — no composition
  theorem or physically separate keys are needed; independence is structural.

In the composition mapping: the MAC key is `tw_key`, the MAC input is the full ciphertext (including chunk
structure), and `N`/`AD` are bound to `tw_key` via the KDF (§5.3). The `Decrypt` oracle enables $S$ tag-guess
tests; by the tag uniformity corollary (§6.7), each succeeds with probability $1/2^{8\tau}$.

$$\varepsilon_{\mathrm{ind\text{-}cca2}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{t}{2^{256}} + \frac{S}{2^{8\tau}}$$

The $t / 2^{256}$ term is key guessing, dominated by the sponge term (see §6.3).

### 6.4 Authenticity (INT-CTXT)

*This property is stated for `TreeWrap-AEAD` (§5.3).*

**Game.** The adversary has access to `Encrypt` and `Decrypt` oracles under a random key `K`. The adversary is
nonce-respecting for encryption queries (each uses a fresh `N`); decryption queries may use any nonce. The adversary
wins by producing $(N, \mathit{AD}, \mathit{CT} \| \mathit{tag})$ such that `Decrypt(K, N, AD, CT ‖ tag)` returns
`M ≠ ⊥` and `CT ‖ tag` was not previously returned by `Encrypt(K, N, AD, ·)`.

**Theorem.**

$$\varepsilon_{\mathrm{int\text{-}ctxt}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{t}{2^{256}} + \frac{S}{2^{8\tau}}$$

The $t / 2^{256}$ term is key guessing, dominated by the sponge term (see §6.3).

**Proof sketch.** After the sponge→RO hop (cost $(\sigma+t)^2/2^{c+1}$), each fresh nonce yields an independent,
uniformly random `tw_key` (injective `encode_string` encoding + RO independence; see §6.3 hop 1). The adversary may
also guess the secret key $K$ with probability $t / 2^{256}$ (stated explicitly in the bound above). The tag
uniformity corollary (§6.7) states that the tag is uniform over $8\tau$ bits for any ciphertext not previously
queried under the same key. The INT-CTXT freshness condition — "CT‖tag was not previously returned by
`Encrypt` on the same `(N, AD)`" — maps directly: same nonce and AD imply the same `tw_key` (via the KDF),
and the game excludes the exact CT returned by `Encrypt`, so the forgery ciphertext is novel under that key.
Each of $S$ forgery attempts therefore succeeds with probability $1/2^{8\tau}$; a union bound gives
$S/2^{8\tau}$.

> [!WARNING]
> **Tag truncation.** When the caller truncates the tag to $T < \tau$ bytes, the forgery bound becomes
> $(\sigma + t)^2 / 2^{c+1} + S / 2^{8T}$. For $T = 16$ (128-bit truncated tags),
> each forgery attempt succeeds with probability $1/2^{128}$.

### 6.5 Committing Security (CMT-4)

*This property is stated for `TreeWrap-AEAD` (§5.3), but does not depend on tag verification — it applies equally to
the bare TreeWrap primitive (see §6.5.1).*

**Game.** The adversary produces $(K, N, \mathit{AD}, M) \neq (K', N', \mathit{AD}', M')$ such that
`Encrypt(K, N, AD, M) = Encrypt(K', N', AD', M')`. This is a non-oracle game: the adversary chooses all inputs
(including keys) and performs all computation itself. Consequently, the adversary's ability to search for collisions
is bounded by its total computational budget, not by a count of online queries.

**Theorem.**

$$\varepsilon_{\mathrm{cmt4}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{(\sigma + t)^2}{2^{8\tau+1}}$$

where $\sigma + t$ is the adversary's total Keccak-p evaluation budget (construction evaluations and direct
primitive queries combined). For $\tau = 32$ (so $8\tau + 1 = c + 1 = 257$), the two terms are equal and the bound
simplifies to $(\sigma + t)^2 / 2^c$.

**Proof sketch.** Two cases:

1. **Different AEAD context** ($(K,N,\mathit{AD}) \neq (K',N',\mathit{AD}')$). After the sponge→RO hop, the
   injective `encode_string` encoding (§5.3) ensures distinct `(K, N, AD)` triples produce distinct TurboSHAKE128
   inputs, which map to distinct random oracle inputs. In the RO world, distinct inputs produce independent
   uniform outputs — so the KDF yields independent, uniformly random `tw_key` values (distinct except with
   birthday probability $Q^2 / 2^{257}$, already captured by the sponge term). Conditioned on distinct keys:
   the ciphertext may coincide, but distinct (key, ciphertext) pairs produce distinct tags except with probability
   bounded by tag collision resistance (§6.6).

2. **Same context, different messages** (same $(K,N,\mathit{AD})$, so same `tw_key`, but $M \neq M'$). Same key
   implies the same chunk boundaries: the chunk structure is determined by `tw_key` and $|M|$, and the CMT-4 game
   requires $|\mathit{CT}| = |\mathit{CT}'|$, so $|M| = |M'|$. With identical key and chunk boundaries, encryption
   is a bijection within each chunk (`encrypt`/`decrypt` are inverses for the same key), so $M \neq M'$ implies
   $\mathit{CT} \neq \mathit{CT}'$. This contradicts the equal-ciphertext requirement.

CMT-4 is a single-stage game: the adversary outputs all inputs at once and a deterministic check follows, with no
oracle interaction. This is a necessary precondition for applying the sponge indifferentiability composition
theorem (which requires that the distinguisher's use of the ideal primitive be simulatable without rewinding).

In Case 1, after the sponge→RO hop (cost $(\sigma + t)^2 / 2^{c+1}$), distinct (key, ciphertext) pairs produce
tags that are pseudorandom and pairwise independent under the PRF reduction (by the tag collision resistance
argument in §6.6). Since the adversary can evaluate at
most $\sigma + t$ distinct (key, ciphertext) pairs (each evaluation costs at
least one Keccak-p call). The collision probability among these evaluations is the standard birthday bound on the
$8\tau = 256$-bit tag output: $(\sigma + t)^2 / 2^{8\tau+1}$.

The bound uses $\sigma + t$ as an upper bound on the number of distinct (key, ciphertext) evaluations. This is
conservative: each full AEAD evaluation on a message of length $L$ costs at least $\lceil L / B \rceil$ Keccak-p
calls, so the effective number of trials is at most $(\sigma + t) / \lceil L / B \rceil$ for messages of length $L$.
The bound is therefore tighter for long messages. This also absorbs the factor-of-2 conservatism from counting
individual evaluations rather than collision pairs.

This committing property is inherent to the construction — it does not require any additional processing or a second
pass over the data, unlike generic CMT-4 transforms applied to non-committing AE schemes.

> [!WARNING]
> **Tag truncation and committing security.** When the caller truncates the tag to $T < \tau$ bytes, the birthday
> term becomes $(\sigma + t)^2 / 2^{8T+1}$, governed by the truncated output length $8T$ bits rather than the full
> $8\tau$ bits. Since the adversary controls the keys in the CMT-4 game, this term reflects offline collision search,
> not online query count. For $T = 16$ (128-bit truncated tags), the birthday term is $(\sigma + t)^2 / 2^{129}$,
> giving constant advantage at $\sigma + t \approx 2^{64}$: a 128-bit truncated tag provides only $\approx$64-bit
> committing security. Callers that truncate the tag and rely on committing security MUST ensure that the
> adversary's computational budget remains well below $2^{4T}$ Keccak-p evaluations. (The KDF output collision
> term $(\sigma + t)^2 / 2^{c+1}$ is unaffected by tag truncation, since it depends on the 256-bit `tw_key`,
> not the tag length.)

### 6.5.1 Caller Obligations

The theorems in §6.3–§6.5 are properties of `TreeWrap-AEAD` (§5.3), which internally
derives unique keys, verifies tags, and withholds plaintext on verification failure. The bare TreeWrap primitive
(`EncryptAndMAC`/`DecryptAndMAC`) does none of these — it takes a raw key, always returns plaintext, and always
returns the computed tag without comparing it to anything. The following table summarizes what each AEAD security
property requires of the caller, in increasing order of obligation:

| Property              | Caller obligation                                                                                                                                                                                                                                                                                                                                      |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **CMT-4** (§6.5)      | None. Committing security is inherent to the construction and does not depend on tag verification.                                                                                                                                                                                                                                                     |
| **IND-CPA** (§6.3)    | The caller MUST ensure that each `EncryptAndMAC` invocation uses a unique key. In `TreeWrap-AEAD` (§5.3), uniqueness follows from the injective encoding applied to a fresh nonce. Callers that manage keys directly MUST guarantee uniqueness by other means. Key reuse leaks plaintext XOR differences within the first block (§6.1).                |
| **INT-CTXT** (§6.4)   | The caller MUST compare the returned tag against the expected value using a constant-time equality check (§6.11) and MUST reject the plaintext if the comparison fails. Without tag verification, the bare primitive provides no authenticity guarantee — any ciphertext decrypts to *some* plaintext with a valid-looking tag.                        |
| **IND-CCA2** (§6.3.1) | The caller MUST NOT release or act on the plaintext returned by `DecryptAndMAC` before successful tag verification. The bare primitive intentionally supports release of unverified plaintext (RUP) for protocols that need it, but RUP forfeits CCA2 security: an attacker can flip ciphertext bits and observe the effect on the released plaintext. |

The bare primitive directly provides, without any wrapper, the following properties under a uniformly random key:
ciphertext pseudorandomness (a single-invocation consequence of the §6.3 core argument), tag PRF security (§6.7),
tag collision resistance (§6.6), chunk reordering protection (§6.8), and committing security (§6.5).

### 6.6 Tag Collision Resistance

*This property is stated for the bare TreeWrap primitive.*

For $Q$ distinct (key, ciphertext) pairs, the probability that `EncryptAndMAC` (or `DecryptAndMAC`) produces a tag
collision is bounded by:

$$\varepsilon_{\mathrm{coll}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{Q^2}{2^{8\tau+1}}$$

Two components:

- **Sponge-vs-RO**: $(\sigma + t)^2 / 2^{c+1}$ — the cost of replacing all sponge evaluations with random oracle
  evaluations via sponge indifferentiability.
- **RO-world birthday**: $Q^2 / 2^{8\tau+1}$ — the birthday collision probability among $Q$ pseudorandom $8\tau$-bit
  tag values (each a PRF output on a distinct input). For $\tau = 32$, this is $Q^2 / 2^{257}$.

The RO-world term is negligible for practical $Q$.
Simplified: $\varepsilon_{\mathrm{coll}} \leq (\sigma + t)^2 / 2^{c+1}$.

Distinct (key, ciphertext) pairs correspond to distinct (key, plaintext) pairs (by the encrypt bijection for fixed
key), which produce distinct leaf sponge inputs via the injective encoding (§6.12, "Injectivity of the encoding") —
after the sponge-to-RO hop (§6.2), these distinct inputs produce independent random outputs except with
probability bounded by the sponge indifferentiability term. Distinct chain
value sequences produce distinct $\mathit{final\_input}$ values (the encoding is injective). Distinct inputs to
TurboSHAKE128 collide with probability bounded by the birthday term. Evaluations with $n = 1$ (domain `0x61`) and
$n > 1$ (domain `0x64`) use disjoint RO domains, so their outputs are pairwise independent; cross-type
collisions contribute at most $Q^2 / 2^{257}$, already captured by the birthday term.

### 6.7 Tag PRF Security

This property is stated for the **bare TreeWrap primitive** (not `TreeWrap-AEAD`), because calling protocols may use
the tag value directly — for example, absorbing it into ongoing transcript state rather than solely verifying it for
authentication.

Under a uniformly random key, the TreeWrap tag is a pseudorandom function of the plaintext, equivalently of the
ciphertext (since encryption is a bijection for a fixed key; see §6.12, Step 2). Specifically, for any fixed ciphertext,
the tag output of `EncryptAndMAC` (or `DecryptAndMAC`) is indistinguishable from a uniformly random $\tau$-byte string.

$$\varepsilon_{\mathrm{prf}} \leq \frac{(\sigma + t)^2}{2^{c+1}} + \frac{t}{2^{256}}$$

The two terms account for different failure events, combined by a union bound:

- $(\sigma + t)^2 / 2^{c+1}$ is the sponge indifferentiability cost: the probability that the adversary can
  distinguish the Keccak sponge from a random oracle, using $\sigma$ online construction queries and $t$ offline
  permutation queries. This is a *structural* distinguishing advantage — it measures whether the sponge behaves
  like a random oracle, not whether the adversary learns the key.
- $t / 2^{256}$ is the key-guessing probability: the chance that one of the adversary's $t$ offline permutation
  evaluations happens to hit the 256-bit key prefix, allowing it to predict the PRF output directly. (This
  assumes the sponge indifferentiability simulator makes at most one random oracle query per permutation query,
  which holds for the absorbing-phase simulator of Bertoni et al.)

These are distinct events even though $t$ appears in both terms. The sponge term bounds the advantage of any
distinguisher against the sponge construction (a generic structural property); the key-guessing term bounds the
probability of a specific event (key recovery) that would break the PRF regardless of sponge quality. Neither
subsumes the other, so both appear in the union bound. In practice, $t / 2^{256} \ll (\sigma + t)^2 / 2^{257}$
for all relevant parameter ranges, so the key-guessing term is negligible.

This is also distinct from the tag-guessing term $S / 2^{8\tau}$ in INT-CTXT (§6.4), which counts online
verification attempts. Since $8\tau = 256$, the key-guessing and tag-guessing terms share the same denominator, but
they measure different adversarial capabilities (offline key search vs. online forgery).

The argument follows from the monolithic sponge indifferentiability reduction (§6.12). After replacing all sponge
evaluations with random oracle evaluations, each leaf defines a keyed PRF $F_K(i, P_i)$ with the secret key as a
prefix (§6.12, Step 2). Distinct leaf indices produce distinct PRF inputs, so for $n > 1$ all chain values are
simultaneously pseudorandom. For $n = 1$, the tag is squeezed directly from the leaf state with domain byte `0x61`,
which is a PRF output under the secret key. For $n > 1$, the tag is
$\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x64}, \tau)$ where $\mathit{final\_input}$ is a deterministic,
injective encoding of the chain values. Domain byte `0x64` separates tag accumulation from the leaf ciphers
(`0x60` – `0x63`). By the same bad-event argument as §6.3 hop 2: the adversary queries the random oracle at
$\mathit{final\_input}$ with probability at most $t / 2^{8Cn}$; conditioned on this not occurring, the tag is
uniformly random.

**Corollary (tag uniformity).** For any ciphertext not previously queried under the same key, the tag is uniformly
distributed over $8\tau$ bits, independent of the adversary's view. This follows directly from the PRF property: a
PRF output on a fresh input is indistinguishable from uniform.

Protocols that use the tag as a contribution to ongoing state (rather than solely for authentication) require this
stronger property.

### 6.8 Chunk Reordering

*This property is stated for the bare TreeWrap primitive.*

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes
which leaf decrypts which data, producing different chain values and a different tag. Additionally, since leaf indices
are bound at initialization, an attacker cannot cause chunk $i$'s ciphertext to be decrypted as chunk $j$ — the
decryption will produce garbage and the chain value will not match. Truncating or extending the ciphertext changes the
number of chunks $n$, which changes $\mathrm{length\_encode}(n)$ in the final node input, producing a different tag.

### 6.9 Empty Plaintext

When plaintext is empty, $n = 1$. A single leaf is initialized and the fast-path is used. The tag is derived directly
from the cipher state after `init` via `single_node_tag()`, with no `encrypt` calls or final node structure. This
ensures `DecryptAndMAC` with an empty ciphertext computes the same tag as `EncryptAndMAC` with an empty plaintext.

### 6.10 Tag Accumulation Structure

Chain values are accumulated using the Sakura tree hash coding (Guido Bertoni et al., "Sakura: a flexible coding for
tree hashing"), the same framing used by KangarooTwelve (RFC 9861). TreeWrap uses a symmetric flat tree where all $n$
chunks are processed as inner nodes producing chain values. This differs from KangarooTwelve's asymmetric topology
(kangaroo hopping), where the first chunk's data is interleaved directly into the final node as native payload and only
$n-1$ CVs follow. In TreeWrap, the final node is a pure chaining hop with no native payload — all $n$ chain values
appear after the hop indicator, and `right_encode(n)` encodes the total number of CVs.

The final node input is constructed as:

```text
final_input ← 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ cv[0] ‖ cv[1] ‖ ... ‖ cv[n−1] ‖ right_encode(n) ‖ 0xFF 0xFF
```

The components of this encoding are:

- **`0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`** (8 bytes): The Sakura chaining hop indicator. The byte `0x03`
  (`0b00000011`) encodes two flags: bit 0 signals that inner-node chain values follow, and bit 1 signals a single-level
  tree (chain values feed directly into the final node without further tree reduction). The seven zero bytes encode
  default tree parameters (no sub-tree interleaving).

- **`cv[0] ‖ cv[1] ‖ ... ‖ cv[n−1]`**: Chain values from all $n$ chunks, produced by independent leaf cipher
  evaluations. Unlike KangarooTwelve, the first chunk is not interleaved — all chunks are treated symmetrically.

- **`right_encode(n)`**: The total number of inner-node chain values, encoded per KangarooTwelve's convention
  (big-endian with no leading zeros, followed by a byte giving the encoding length).

- **`0xFF 0xFF`**: The Sakura tree hash terminator, signaling the end of the final node input.

This is processed by TurboSHAKE128 with domain separation byte 0x64, separating TreeWrap tag accumulation from both
KT128 hashing (0x07) and TreeWrap leaf ciphers (0x60 – 0x63).

The encoding is injective: chain values are fixed-size ($C$ bytes each), the chaining hop indicator and terminator are
fixed constants, and `right_encode` uniquely determines $n$. The number of chunks is also determined by the ciphertext
length, which is assumed to be public.

### 6.11 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext
values. The chunk index is not secret and does not require side-channel protection. Specific hazards include:

- **Data-dependent memory access.** SIMD or vectorized Keccak implementations must not use lookup tables indexed by
  state bytes. All memory access patterns must be independent of key and plaintext values.
- **Variable-time tag comparison.** The caller is responsible for tag verification (§1). Tag comparison MUST use a
  constant-time equality check to prevent timing oracles.
- **Variable-time partial block handling.** The final chunk may be shorter than $B$ bytes. Implementations must not
  branch on plaintext byte values when processing partial blocks; the *length* of the partial block is public and
  need not be protected.

### 6.12 Concrete Security Reduction

Each leaf cipher operates on the Keccak-p[1600,12] permutation with capacity $c = 256$ bits. During encryption, each
ciphertext byte is written back into the sponge rate. The security argument proceeds in two steps: a syntactic
rewriting that is information-theoretic, followed by a single application of the sponge indifferentiability theorem.

**Step 1: Ciphertext-write to XOR equivalence.** During encryption, each ciphertext byte
$\mathit{CT}_j = P_j \oplus S[\mathit{pos}]$ is written into the state at position $\mathit{pos}$. Writing $\mathit{CT}_j$
into $S[j]$ when $S[j]$ currently holds $Z[j]$ (the permutation output) is equivalent to XORing $S[j]$ with
$\mathit{CT}_j \oplus Z[j]$. Since $\mathit{CT}_j = P_j \oplus Z[j]$, the equivalent XOR input is
$\mathit{CT}_j \oplus Z[j] = P_j$ — the plaintext byte. This is a per-position algebraic identity with no
computational cost.

After rewriting each ciphertext write as the equivalent XOR, the remaining operations are: (a) XOR absorption of key/index
material during `init` (already standard sponge absorption), and (b) `pad_permute` calls that XOR a domain byte at
position $\mathit{pos}$ and `0x80` at position $R - 1$ — exactly TurboSHAKE's `pad10*1` padding. The capacity portion
(bytes $R$ through 199) is never directly read or written. Therefore, after the rewriting, each leaf's full computation
is a standard $\mathrm{Keccak}[256]$ sponge evaluation. Note that the concatenated sponge input consists of
$R$-byte blocks, each self-padded via `pad10*1`. When absorbed by a standard sponge $R$ bytes at a time, the
absorption boundaries align with the block boundaries, reproducing the leaf's per-block `pad_permute` behavior
exactly. The standard sponge's own final padding is never triggered because every block is already $R$-byte
aligned — this is the same technique used by Sakura tree hashing.

**Keyed duplex interpretation.** The rewritten leaf is equivalently a keyed duplex construction (Bertoni et al.,
"Duplexing the Sponge," SAC 2011): the init block absorbs key material ($K \| [i]_{\mathrm{64LE}}$), and each
subsequent block absorbs plaintext and produces rate bytes that serve as keystream (squeezed before the next
absorption). The duplex security theorem (ibid., Theorem 1) therefore covers not just the terminal squeeze (chain
value or tag) but all intermediate rate outputs — precisely the bytes XORed with plaintext to form ciphertext.
This observation is used in §6.3 hop 2 to justify keystream pseudorandomness. For tighter bounds in the keyed
setting, see Mennink–Reyhanitabar–Vizár (Eurocrypt 2015); the resulting bound remains $(\sigma+t)^2/2^{c+1}$.

**Equivalent sponge input.** Define $\mathrm{pad}(X, d)$ as the $R$-byte string $X \| d \| 0^{R-2-|X|} \| \texttt{0x80}$,
where $|X| \leq R - 2$ (the data, domain byte, and terminator fit in one rate block). This is `pad10*1` applied to
$X$ with domain byte $d$.

For a leaf with key $K$, index $i$, plaintext $P$, and final domain byte $d_f$ (`0x63` for chain value, `0x61` for
single-node tag), partition $P$ into $(R-1)$-byte segments: $P = P_1 \| P_2 \| \cdots \| P_m \| P_*$, where
$|P_j| = R - 1$ for $1 \leq j \leq m$ and $|P_*| < R - 1$ (the final segment, possibly empty). The equivalent
sponge input is a single byte string:

$$\mathrm{sponge\_input}(K, i, P, d_f) = \mathrm{pad}(K \| [i]_{\mathrm{64LE}},\, \texttt{0x60}) \;\|\; \mathrm{pad}(P_1,\, \texttt{0x62}) \;\|\; \cdots \;\|\; \mathrm{pad}(P_m,\, \texttt{0x62}) \;\|\; \mathrm{pad}(P_*,\, d_f)$$

When $m = 0$ (plaintext shorter than $R - 1$ bytes, including the empty case), the intermediate blocks vanish and
the input is $\mathrm{pad}(K \| [i]_{\mathrm{64LE}},\, \texttt{0x60}) \| \mathrm{pad}(P_*,\, d_f)$. In the
empty-plaintext case ($P = \epsilon$, $P_* = \epsilon$), the final block is $d_f \| 0^{R-2} \| \texttt{0x80}$.
This is well-defined and injective: it is distinct from any final block with non-empty $P_*$ (the domain byte
$d_f$ appears at position 0 instead of position $|P_*| > 0$).

This is a function of $(K, i, P)$ — the **plaintext**, not the ciphertext. This follows directly from the per-byte
identity: the XOR-equivalent of overwriting with ciphertext absorbs plaintext. However, for a fixed key, encryption
is a bijection ($P \neq P'$ implies $C \neq C'$ for the same key; see §6.5 Case 2), so the sponge input is
equivalently determined by $(K, i, C)$. The tag is therefore both a PRF of the plaintext and a PRF of the ciphertext
(see Step 2).

**Injectivity of the encoding.** The encoding $(K, i, P) \mapsto \mathrm{sponge\_input}(K, i, P, d_f)$ is injective.
We show that distinct inputs produce distinct byte strings by case analysis.

*Claim:* If $(K, i, P) \neq (K', i', P')$ (with the same $d_f$), then
$\mathrm{sponge\_input}(K, i, P, d_f) \neq \mathrm{sponge\_input}(K', i', P', d_f)$.

*Block structure recovery.* Each $\mathrm{pad}(X, d)$ block is exactly $R$ bytes, so the sponge input decomposes
uniquely into $R$-byte blocks. The block count is $m + 2$ (one init, $m$ intermediate, one final). Since $m$ is
determined by $|P|$ and the block boundaries are at fixed $R$-byte offsets, both the number of blocks and the
partition into blocks are uniquely recoverable.

*Case 1: Different block counts* ($|P| \neq |P'|$ and the difference crosses an $(R-1)$-byte segment boundary).
The sponge inputs have different lengths and are therefore distinct.

*Case 2: Same block count, different init material* ($(K, i) \neq (K', i')$). The init block is
$\mathrm{pad}(K \| [i]_{\mathrm{64LE}},\, \texttt{0x60})$. Since $|K| = C$ and $|[i]_{\mathrm{64LE}}| = 8$ are
fixed, and $C + 8 = 40 < R - 1 = 167$, the init material always fits in a single block. Distinct $(K, i)$ pairs
produce distinct 40-byte prefixes within the init block, so the blocks differ.

*Case 3: Same init material, different plaintexts* ($(K, i) = (K', i')$, $P \neq P'$). Sub-cases:

- *3a: Same length* ($|P| = |P'|$, so same $m$ and same $|P_*| = |P'_*|$). The plaintexts differ at some byte
  position, which falls in some block (intermediate or final). That block's data field differs, so the padded block
  differs. (The data field occupies bytes $0, \ldots, |X|-1$ of $\mathrm{pad}(X, d)$; the domain byte at position
  $|X|$ and the terminator at position $R-1$ are identical for same-length data with the same domain byte.)
- *3b: Different length, same block count* ($|P| \neq |P'|$ but $m = m'$, so $|P_*| \neq |P'_*|$). In the final
  block, the domain byte $d_f$ appears at position $|P_*|$ in one and $|P'_*|$ in the other. Since
  $d_f \in \{\texttt{0x61}, \texttt{0x63}\}$ and the intervening zero-padding differs, the final blocks differ.

*Cross-$d_f$ injectivity.* The injectivity claim above is stated for fixed $d_f$. Across different $d_f$ values,
sponge inputs for $n = 1$ leaves ($d_f = \texttt{0x61}$) and $n > 1$ leaves ($d_f = \texttt{0x63}$) are also
distinct: the final block contains $d_f$ at position $|P_*|$, and since $\texttt{0x61} \neq \texttt{0x63}$,
any two evaluations with different $d_f$ produce different final blocks (even for identical $K$, $i$, and $P$).

*Domain byte separation across block types.* The init block uses `0x60`, intermediate blocks use `0x62`, and the
final block uses `0x61` or `0x63`. Since the block positions are recoverable (first block is always init, last is
always final, middle are intermediate), no block from one type can be confused with another. This is not needed for
injectivity of the same-$d_f$ encoding, but it ensures that leaf sponge inputs are also disjoint from tag
accumulation inputs (domain byte `0x64`) and KDF inputs (domain byte `0x65`) — a property used in §6.3 and §6.3.1.

The injectivity is a property of the encoding format. The encrypt/decrypt bijection is a separate property (used in
the CMT-4 proof §6.5 and to establish that the PRF of plaintext is equivalently a PRF of ciphertext).

After this rewriting, all computations in a TreeWrap invocation — $n$ leaf sponge evaluations plus one optional tag
accumulation (TurboSHAKE128 with domain byte `0x64`) — are standard sponge evaluations on distinct inputs. Leaf inputs
differ by index; the tag evaluation is separated by domain byte.

**Step 2: Monolithic indifferentiability reduction.** The sponge indifferentiability theorem replaces all sponge
evaluations simultaneously with random oracle evaluations in a single reduction. After this replacement, each leaf
computes $\mathrm{cv}[i] = \mathcal{O}(K \| [i]_{\mathrm{64LE}} \| P_i)$ where $\mathcal{O}$ is the random oracle
and $K$ is the secret key. Because $K$ is a 256-bit secret prefix unknown to the adversary, each leaf defines a
keyed PRF: $F_K(i, P_i) = \mathcal{O}(K \| [i]_{\mathrm{64LE}} \| P_i)$. Distinct leaf indices produce distinct
oracle inputs, so for $n > 1$ all $n$ chain values are simultaneously pseudorandom (each is a PRF output on a
distinct input). For $n = 1$, the single leaf directly outputs the tag via domain byte `0x61`, which is a direct PRF
output under the secret key. For $n > 1$, the tag is
$\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x64}, \tau)$ where
$\mathit{final\_input}$ is a deterministic, injective encoding of the chain values. Domain byte `0x64` separates
tag accumulation from leaf evaluations (`0x60`–`0x63`). Tag pseudorandomness follows from the bad-event argument
in §6.3 hop 2: the adversary queries the random oracle at $\mathit{final\_input}$ with probability at most
$t / 2^{8Cn}$; conditioned on this not occurring, the tag is uniformly random.

Since encryption is a bijection for a fixed key (§6.5 Case 2), the PRF $F_K(i, P_i)$ is equivalently a PRF of the
ciphertext: distinct ciphertexts under the same key correspond to distinct plaintexts, producing distinct sponge
inputs. The tag is therefore pseudorandom as a function of either the plaintext or the ciphertext.

The advantage of this reduction is bounded by:

$$\varepsilon_{\mathrm{indiff}} \leq \frac{(\sigma + t)^2}{2^{c+1}}$$

where $\sigma$ is the total online data complexity across all sponge evaluations (all leaves and the tag computation
combined), measured in Keccak-p blocks, and $t$ is the adversary's total offline computational complexity in Keccak-p
evaluations. The number of leaves does not appear as a separate factor — the online queries from all leaves are already
counted in $\sigma$, and the indifferentiability theorem handles all sponge evaluations at once rather than requiring a
per-leaf hybrid argument.

**Multi-invocation security.** Multi-invocation security follows from the `TreeWrap-AEAD` game definitions
(§6.3–§6.5), which permit multiple oracle queries under the same key. Each query uses a fresh nonce, producing an
independent TreeWrap key via the KDF (§5.3). The indifferentiability reduction bounds the entire multi-query
interaction at once: $\sigma$ counts the total online Keccak-p calls across all queries (including KDF evaluations),
and the sponge indifferentiability theorem replaces all sponge evaluations simultaneously. Cross-query independence
of TreeWrap keys is structural: the injective `encode_string` encoding ensures distinct `(K, N, AD)` triples produce
distinct TurboSHAKE128 inputs (domain byte `0x65`), which yield independent uniform outputs in the RO world.

**Multi-user security.** In the multi-user setting with $M$ users, each with an independent key, the sponge
indifferentiability term scales naturally with the total data complexity: $\sigma$ counts all online Keccak-p calls
across all users, and the indifferentiability theorem handles them in a single reduction. The $M$ factor only
affects key-guessing: an adversary making $t$ offline calls can target any of $M$ independent 256-bit keys, giving
a key-guessing advantage of $M \cdot t / 2^{256}$. For $M \leq 2^{32}$ users, this remains negligible relative to
the sponge indifferentiability term at $\sigma + t \leq 2^{128}$.

## 7. Comparison with Traditional AEAD

TreeWrap differs from traditional AEAD in several respects. This document defines a concrete AEAD construction
(TreeWrap-AEAD, §5.3) for security analysis purposes, but the core primitive remains a bare
`EncryptAndMAC`/`DecryptAndMAC` interface.

**No internal tag verification.** Traditional AEAD schemes (AES-GCM, ChaCha20-Poly1305, etc.) perform tag comparison
inside the `Open`/`Decrypt` function and return ⊥ on failure, ensuring plaintext is never released before
authentication. TreeWrap's `DecryptAndMAC` always returns both plaintext and tag, leaving verification to the caller.
This supports protocol frameworks that need the tag for transcript state advancement regardless of verification outcome.

**Nonce-free bare primitive.** The bare TreeWrap primitive takes only a key and plaintext. It does not accept a nonce or
associated data. Nonce handling is the KDF's responsibility: `TreeWrap-AEAD` (§5.3) accepts nonces, but they are
consumed by the concrete TurboSHAKE128-based KDF to derive a unique TreeWrap key, not passed to TreeWrap itself. The key MUST be pseudorandom
(indistinguishable from uniform) and unique per invocation (see §5.1).

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs — they prove authenticity but are not
necessarily pseudorandom. TreeWrap's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (§6.7). This stronger property supports protocols that absorb the tag into ongoing state.

### 7.1. Usage Limits

Günther, Thomson, and Wood tabulate concrete usage limits for AES-GCM and ChaCha20-Poly1305 as functions of a
target advantage $p$. TreeWrap's security bounds (§6) are dominated by a single sponge indifferentiability term
$(\sigma + t)^2 / 2^{c+1}$ with $c = 256$, which yields structurally simpler limits. Here $\sigma + t$ counts all
Keccak-p[1600,12] calls across every key in the system (§6.2).

Setting the total advantage $\leq p$:

| Property                    | Bound                                         | $p = 2^{-32}$             | $p = 2^{-50}$             |
|-----------------------------|-----------------------------------------------|---------------------------|---------------------------|
| Confidentiality (IND-CPA)   | $(\sigma+t)^2 / 2^{257} \leq p$               | $\sigma+t \leq 2^{112.5}$ | $\sigma+t \leq 2^{103.5}$ |
| Integrity (INT-CTXT)        | $+ \; S / 2^{256}$                            | $S \leq 2^{224}$          | $S \leq 2^{206}$          |
| Auth. Encryption (IND-CCA2) | $(\sigma+t)^2 / 2^{257} + S / 2^{256} \leq p$ | same                      | same                      |

**Multi-key.** The bounds above are already whole-system: $\sigma + t$ is the total Keccak-p call count across all $u$
keys (§6.2). With $u$ keys the per-key budget is $(\sigma + t)/u$, but no additional multi-key degradation term arises.
This contrasts with AES-GCM, where multi-key security introduces per-key block-count limits that tighten as $u$ grows.

**Comparison with AES-128-GCM.** At $p = 2^{-50}$ with 1500-byte messages, Günther, Thomson, and Wood (Table 2) limit
AES-128-GCM to $2^{32.5}$ queries per key. TreeWrap at the same advantage permits $\sigma + t \leq 2^{103.5}$ Keccak-p
calls system-wide — roughly $2^{100}$ messages even at maximum tree depth — a factor of approximately $2^{67}$.

## 8. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007. Establishes
  the flat sponge claim (sponge indifferentiability from a random oracle).
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint
  2013/231. Defines the tree hash coding framework used by KangarooTwelve and TreeWrap.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.
- Günther, F., Thomson, M., and Wood, C. A. "Usage Limits on AEAD Algorithms." draft-irtf-cfrg-aead-limits-11. Concrete
  usage limit tables for AES-GCM and ChaCha20-Poly1305; referenced in §7.1.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass Authenticated Encryption
  and Other Applications." SAC 2011. IACR ePrint 2011/499. Proves that duplex outputs are pseudorandom under the sponge
  indifferentiability assumption (Theorem 1); establishes that all intermediate rate outputs — not just terminal squeezes
  — are covered by the duplex security bound.
- Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex: Beyond the Birthday
  Bound." Eurocrypt 2015. Provides direct ideal-permutation-model bounds for the keyed duplex, giving a tighter reduction
  than routing through sponge indifferentiability.
- Daemen, J., Mennink, B., and Van Assche, G. "Full-State Keyed Duplex with Built-in Multi-User Support." Asiacrypt 2017.
  Extends the keyed duplex bounds to the multi-user setting; referenced in §6.12 multi-user discussion.
- Luykx, A. and Paterson, K. G. "Limits on Authenticated Encryption Use in TLS." IACR ePrint 2024/051 (originally 2016).
  Derives the underlying AES-GCM and ChaCha20-Poly1305 bounds that Günther et al. tabulate.

## 9. Test Vectors

All vectors use the following inputs:

- **Key:** 32 bytes `00 01 02 ... 1f`
- **Plaintext:** `len` bytes `00 01 02 ... (len−1) mod 256`

Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.

### 9.1 Empty Plaintext (MAC-only, $n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 0                                                                  |
| ct    | (empty)                                                            |
| tag   | `668f373328d7bb108592d3aaf3dacdabcccff2ca302677c6ea33addf4f72990d` |

`DecryptAndMAC` with the same key and empty ciphertext produces the same tag.

### 9.2 One-Byte Plaintext ($n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 1                                                                  |
| ct    | `f1`                                                               |
| tag   | `c04761e374ccb3a926eeabbe49698122b5d72d362deb35c04a22132676309c35` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`8e419b1ad3363b42ebdf788c914c94e826a0d4864b6eb828c33ac460a60f7cee`.

### 9.3 B-Byte Plaintext (exactly one chunk, $n = 1$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8192                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `16ca20542882e63361f8dce572834de742e828f3046cdffc90b5b79faa8e86e2` |

Flipping bit 0 of `ct[0]` yields tag
`252c145ed845841ee9156ed46febaf03ad213d727256c761a36db0bf10901ea8`.

### 9.4 B+1-Byte Plaintext (two chunks, minimal second, $n = 2$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8193                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `334010388fc60b70a51e9e0f2e83222549e3231153575e27fce16227ea197bb1` |

Flipping bit 0 of `ct[0]` yields tag
`76398352ca9c7594808135f297f085bda06bb1ccd0f328246e22cedc7ecfdf65`.

### 9.5 4B-Byte Plaintext (four full chunks, $n = 4$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 32768                                                              |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `0329acf4bfa2cf77a2c8ca4318efe18cece2a0ed4ce61950c03059ea146244b0` |

Flipping bit 0 of `ct[0]` yields tag
`579b5003e457831607da1ac382aea6cda97b0dcd2fd8fbbbe0c5124b0ce36260`.

Swapping chunks 0 and 1 (bytes 0–8,191 and 8,192–16,383) yields tag
`e1d0c423874fec642ad161b2700209c74a74b41451cc70f8cc1c6b894cd0aa98`.

### 9.6 Round-Trip Consistency

For all vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as `EncryptAndMAC`.

## Appendix A. Exact Per-Query σ Formula

For a single `TreeWrap-AEAD` query on a message of length $L$ bytes with
$n = \max(1, \lceil L / B \rceil)$ chunks of sizes $\ell_0, \ldots, \ell_{n-1}$, the per-query contribution to
$\sigma$ is:

$$\sigma_{\mathrm{query}} = \underbrace{\left\lceil \frac{|\mathit{kdf\_input}|}{R} \right\rceil}_{\text{KDF}} + \underbrace{\sum_{i=0}^{n-1}\left(1 + \max\!\left(1,\, \left\lceil \frac{\ell_i}{R-1} \right\rceil\right)\right)}_{\text{leaves}} + \underbrace{\mathbb{1}_{n>1} \cdot \left\lceil \frac{|\mathit{final\_input}|}{R} \right\rceil}_{\text{tag accumulation}}$$

where:

- **KDF term.** $|\mathit{kdf\_input}|$ is the byte length of `encode_string(K) ‖ encode_string(N) ‖ encode_string(AD)`.
  Each `encode_string` contributes `left_encode(|x|)` (1–2 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $|\mathit{kdf\_input}| = (2+32) + (2+12) + (2+0) = 50$ bytes, giving
  $\lceil 50 / 168 \rceil = 1$ Keccak-p call.
- **Leaf term.** Each leaf costs $1$ (init `pad_permute`) $+$ $\max(1, \lceil \ell_i / (R-1) \rceil)$ (ciphertext
  block permutations and the final squeeze — at least 1 even for empty chunks). For a full $B = 8192$-byte chunk:
  $1 + \lceil 8192 / 167 \rceil = 1 + 50 = 51$.
- **Tag accumulation term.** Present only when $n > 1$. $|\mathit{final\_input}| = 8 + nC +
  |\mathrm{right\_encode}(n)| + 2$ bytes. For $n = 2$: $|final\_input| = 8 + 64 + 2 + 2 = 76$ bytes, giving
  $\lceil 76 / 168 \rceil = 1$.

## Appendix B. Reference Implementation of Keccak-p[1600,12] and TurboSHAKE128

This appendix provides a reference Python implementation of the cryptographic primitives used by TreeWrap. It
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

### NIST SP 800-185 Encodings

```python
def right_encode(x: int) -> bytes:
    """Big-endian, no leading zeros, followed by byte count. right_encode(0) = 0x00."""
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
    """left_encode(len(x)) ‖ x."""
    return left_encode(len(x)) + x
```
