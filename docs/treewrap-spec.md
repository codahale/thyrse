# TreeWrap: Tree-Parallel Stream Cipher and MAC

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.8</td></tr>
  <tr><th>Date</th><td>2026-03-02</td></tr>
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

> [!WARNING]
> **Safe default.** If you want nonce-based authenticated-encryption semantics, use `TreeWrap-AEAD` (§5.2). The bare
> `EncryptAndMAC`/`DecryptAndMAC` interface is intended for protocols that explicitly manage per-invocation key
> uniqueness and tag-verification policy.

## 2. Parameters

| Symbol | Value             | Description                                           |
|--------|-------------------|-------------------------------------------------------|
| f      | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds)    |
| R      | 168               | Sponge rate (bytes); data rate is R−1 = 167 per block |
| C      | 32                | Capacity (bytes); key and chain value size            |
| τ      | 32                | Tag size (bytes); equal to C for this instantiation   |
| B      | 8192              | Chunk size (bytes), matching KangarooTwelve           |

**Parameter constraints.** $C + 8 \leq R - 1$ (init material `key || LEU64(index)` = $C + 8 = 40$ bytes fits in a
single rate block). $\max(\tau, C) < R$ (tag and chain value outputs fit in a single squeeze block).

## 3. Dependencies

**`TurboSHAKE128(M, D, ℓ)`:** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01 – 0x7F),
and an output length `ℓ` in bytes.

## 4. Leaf Cipher

A leaf cipher operates on a standard Keccak sponge with the same permutation and rate/capacity parameters as
TurboSHAKE128. It uses six domain separation bytes, reserved for TreeWrap:

| Byte   | Usage                        | Procedure(s)                     |
|--------|------------------------------|----------------------------------|
| `0x60` | Init (key/index absorption)  | `init`                           |
| `0x61` | Single-node tag squeeze      | `single_node_tag`                |
| `0x62` | Intermediate encrypt/decrypt | `encrypt`, `decrypt`             |
| `0x63` | Final block (chain value)    | `chain_value`                    |
| `0x64` | Tag accumulation             | `EncryptAndMAC`, `DecryptAndMAC` |
| `0x65` | AEAD key derivation          | `TreeWrap-AEAD`                  |

> [!NOTE]
> **Operational budgeting guidance.** For deployment-level guidance on budgeting Keccak-p calls across multiple
> components (TreeWrap, TurboSHAKE128, KangarooTwelve), see Appendix C (non-normative).

Unlike the XOR-absorb approach used by SpongeWrap, the `encrypt` and `decrypt` operations write ciphertext directly
into the rate rather than XORing plaintext into it. This supports a direct keyed-duplex style analysis (§6), and for
full-rate blocks, a write-only state update is faster than read-XOR-write on most architectures.

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

> [!NOTE]
> `pad_permute` applies standard TurboSHAKE padding (domain byte at `pos`, `0x80` at `R-1`). `init` uses domain byte
> `0x60`, distinct from the intermediate byte `0x62`, ensuring key absorption is domain-separated from ciphertext
> blocks. Both `encrypt` and `decrypt` overwrite the rate with ciphertext, so state evolution is identical regardless of
> direction. `single_node_tag` and `chain_value` begin with `pad_permute` to mix all data before squeezing; both outputs
> fit in a single squeeze block since $\max(\tau, C) = 32 \ll R = 168$.

## 5. TreeWrap

### Notation

- `||`: Byte string concatenation.
- `LEU64(i)`: The 8-byte little-endian encoding of integer `i`.

The NIST SP 800-185 encodings (`left_encode`, `right_encode`, `encode_string`) are defined as Python functions in
Appendix B.

### 5.1 EncryptAndMAC / DecryptAndMAC

**`TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)`**\
**`TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)`**

*Inputs:*

- `key`: A C-byte key. MUST be pseudorandom (computationally indistinguishable from uniform) and unique per invocation
  (no two calls share a key). See the security analysis in §6.
- `plaintext` / `ciphertext`: Data of any length (may be empty). Maximum length is $(2^{64} - 1) \cdot B$ bytes, since
  leaf indices are encoded as 8-byte little-endian integers.

*Outputs:*

- `ciphertext` / `plaintext`: Same length as the input data. Length reveals plaintext length; the chunking structure
  ($n$, $\ell_0, \ldots, \ell_{n-1}$) is public. Protocols requiring length hiding must pad before calling TreeWrap.
- `tag`: A τ-byte MAC tag.

> [!WARNING]
> **Safe default for callers.** Prefer `TreeWrap-AEAD` (§5.2) unless you explicitly need bare
> `EncryptAndMAC`/`DecryptAndMAC` semantics. Bare TreeWrap requires the caller to enforce per-invocation unique
> pseudorandom keys and to perform the correct tag verification policy.

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
available. `decrypt_and_mac` produces the same tag as `encrypt_and_mac` because both `encrypt` and `decrypt` write
ciphertext into the sponge rate (§4). The caller is responsible for comparing the returned tag against an expected
value; TreeWrap does not perform tag verification.

> [!CAUTION]
> For production implementations, avoid repeated byte-string concatenation (`final_input += ...`) when building the
> final node input; prefer preallocation or list/join style buffer construction.

### 5.2 TreeWrap-AEAD

TreeWrap-AEAD is a concrete AEAD construction built on top of the bare TreeWrap primitive. It derives a per-invocation
TreeWrap key from `(K, N, AD)` using TurboSHAKE128, then delegates to `EncryptAndMAC`/`DecryptAndMAC`. This construction
exists for security analysis — calling protocols may use it directly or implement equivalent key derivation.

**Master-key requirement.** `K` MUST have at least 128 bits of min-entropy and MUST be at least 16 bytes long. Uniformly
random 32-byte keys are RECOMMENDED.

**Key derivation:**

```
tw_key ← TurboSHAKE128(encode_string(K) || encode_string(N) || encode_string(AD), 0x65, C)
```

The `encode_string` encoding (§5, NIST SP 800-185) makes the concatenation injective: each field is prefixed with its
`left_encode`d bit-length (`left_encode(8*len(x))`), so no `(K, N, AD)` triple can produce the same TurboSHAKE128 input
as a different triple. Domain byte `0x65` separates key derivation from all other TreeWrap uses of TurboSHAKE128
(`0x60` – `0x64`).

```python
import hmac

def treewrap_aead_encrypt(K: bytes, N: bytes, AD: bytes, M: bytes) -> bytes:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x65, C)
    ct, tag = encrypt_and_mac(tw_key, M)
    return ct + tag

def treewrap_aead_decrypt(K: bytes, N: bytes, AD: bytes, ct_tag: bytes) -> bytes | None:
    tw_key = turboshake128(encode_string(K) + encode_string(N) + encode_string(AD), 0x65, C)
    ct, tag_expected = ct_tag[:-TAU], ct_tag[-TAU:]
    pt, tag = decrypt_and_mac(tw_key, ct)
    return pt if hmac.compare_digest(tag, tag_expected) else None
```

## 6. Security Properties

This section gives a single, explicit reduction path:

1. Prove core properties of the bare primitive `EncryptAndMAC` / `DecryptAndMAC` under a uniformly random, secret
   `tw_key`.
2. Lift those properties to `TreeWrap-AEAD` via the KDF
   `tw_key <- TurboSHAKE128(encode_string(K) || encode_string(N) || encode_string(AD), 0x65, C)`
   and standard verification semantics.

All bounds are in the ideal-permutation model for Keccak-p[1600,12], with capacity $c = 256$ bits and $\tau = 32$ tag
bytes.

**Assumption scope.** Concrete bounds in this section are conditional on Keccak-p[1600,12] behaving as an ideal
permutation at the claimed workloads. This is a modeling assumption, not a proof about reduced-round Keccak-p itself.

> [!IMPORTANT]
> Public cryptanalysis on Keccak-family primitives includes reduced-round results with explicit round counts: practical
> collision-style results are publicly known through 5 rounds in standard Keccak instances, with 6-round collision
> solutions publicly reported for reduced-round contest instances, and structural distinguishers are known at higher
> round counts in the raw-permutation setting (including 8-round distinguishers and 16-round zero-sum distinguishers).
> (See the Keccak Team third-party table and reduced-round references in §8.)
>
> These results do not directly invalidate the TreeWrap heuristic because TreeWrap uses a keyed sponge/duplex setting
> with 256-bit capacity, strict domain separation, and workload limits; nevertheless, future cryptanalysis could change
> the practical margin, so deployments should treat the concrete bounds as conditional.

### 6.1 Model and Notation

Let:

- $\sigma$: total online Keccak-p calls performed by the construction across all oracle queries.
- $t$: adversary offline Keccak-p calls.
- $S$: total number of decryption/verification forgery attempts in one security experiment (per key epoch).
- $Q$: total number of compared outputs in a birthday-style counting argument (per security experiment / key epoch).
- $q_{\mathrm{ctx}}$: number of distinct context strings $X$ queried to the KDF in one security experiment.

Define the common structural term:

$$
\varepsilon_{\mathrm{indiff}} \;\stackrel{\mathrm{def}}{=}\; \frac{(\sigma + t)^2}{2^{c+1}}.
$$

### 6.2 Bare TreeWrap Core Lemmas

Assume a fixed, uniformly random, secret key $K_{tw} \in \{0,1\}^{8C}$.

**Lemma 1 (Leaf duplex pseudorandomness).**
For each leaf index $i$, the leaf computation is a keyed duplex instance initialized with `K_tw || LEU64([i)`; its rate
outputs (keystream bytes and terminal squeeze bytes) are pseudorandom up to $\varepsilon_{\mathrm{indiff}}$ (see §8:
Sponge/duplex analyses and keyed-duplex bounds).

**Lemma 2 (State-direction equivalence).**
For fixed $(K_{tw}, i, C_i)$, `encrypt` and `decrypt` induce identical internal states because both write ciphertext
bytes into the rate.

**Lemma 3 (Fixed-key bijection).**
For fixed $(K_{tw}, i)$, leaf encryption is bijective. Therefore, for a fixed whole-message key and chunking, TreeWrap
induces a bijection between plaintexts and ciphertexts.

**Consequence.**
The tag is a PRF-style output over the keyed transcript; by Lemma 3 it can be viewed equivalently as a keyed function of
plaintext or ciphertext.

### 6.3 Bare TreeWrap Tag Security Statements

#### 6.3.1 Tag PRF Security

For an adversary querying distinct inputs under one secret key:

$$
\varepsilon_{\mathrm{prf}} \le \varepsilon_{\mathrm{indiff}}.
$$

Reason: by Lemma 1, terminal outputs are pseudorandom; the final-node accumulation for $n>1$ is a keyed
transcript-dependent sponge output in the same model, and no extra hybrid model is introduced.

#### 6.3.2 Tag Collision Resistance

For $Q$ distinct ciphertext inputs under one fixed secret key:

$$
\varepsilon_{\mathrm{coll}} \le \varepsilon_{\mathrm{indiff}} + \frac{Q^2}{2^{8\tau+1}}.
$$

The second term is the birthday bound on $8\tau$-bit pseudorandom outputs. By Lemma 3, this is equivalently a fixed-key
bound over distinct plaintext inputs.

### 6.4 Single-Model KDF Lift Lemma

Define the AEAD context encoding:

$$
X = \mathrm{encode\_string}(K)\,\|\,\mathrm{encode\_string}(N)\,\|\,\mathrm{encode\_string}(AD),
$$

and the derived-key map:

$$
F(X) = \mathrm{TurboSHAKE128}(X,\;0x65,\;C).
$$

Modeling dependence for this lift is the TurboSHAKE/Sakura tree-hash analysis line in §8 (RFC 9861, TurboSHAKE paper,
and KangarooTwelve paper), combined with the sponge/duplex ideal-permutation framework.

We analyze KDF and TreeWrap in one ideal-permutation experiment. Let $\mathsf{Bad}_{\mathrm{perm}}$ be the global bad
event for this experiment (the usual sponge/duplex transcript-collision event across all online/offline Keccak-p calls
used by both KDF and TreeWrap). Then:

$$
\Pr[\mathsf{Bad}_{\mathrm{perm}}] \le \varepsilon_{\mathrm{indiff}}.
$$

Conditioned on $\neg\mathsf{Bad}_{\mathrm{perm}}$:

- $F$ behaves as a lazy-sampled random function on distinct context strings $X$.
- For $q_{\mathrm{ctx}}$ distinct contexts, derived-key collisions follow the birthday bound:

$$
\varepsilon_{\mathrm{ctx-coll}} \le \frac{q_{\mathrm{ctx}}^2}{2^{8C+1}}.
$$

This gives a single-model lift from AEAD contexts to per-context TreeWrap keys, with no separate model transition.

### 6.5 TreeWrap-AEAD Confidentiality and Integrity

The AEAD wrapper definition is given in §5.2 (`treewrap_aead_encrypt` / `treewrap_aead_decrypt`) and is used unchanged
here.

Use one hybrid:

- Game $\mathsf{G}_0$: real `TreeWrap-AEAD`.
- Game $\mathsf{G}_1$: replace $F(X)$ with a lazy-sampled random function $R:\{0,1\}^* \rightarrow \{0,1\}^{8C}$ on
  context strings $X$.

By §6.4 (same global ideal-permutation model),

$$
\left|\Pr[\mathsf{G}_0=1]-\Pr[\mathsf{G}_1=1]\right| \le \varepsilon_{\mathrm{indiff}}.
$$

In $\mathsf{G}_1$, each distinct context gets a random per-context key; conditioned on no context-key collision event,
queries reduce directly to bare TreeWrap under random keys.

**Single-accounting rule used below.** For each goal $\Pi \in \{\text{IND-CPA},\text{INT-CTXT},\text{IND-CCA2}\}$, we
upper-bound:

$$
\mathrm{Adv}_{\Pi} \le \Pr[\mathsf{Bad}_{\mathrm{perm}}] + \Pr[\mathsf{CtxColl}] + \mathrm{Adv}_{\Pi}^{\mathrm{bare}}\!\mid_{\neg \mathsf{Bad}_{\mathrm{perm}}\wedge \neg \mathsf{CtxColl}}.
$$

Under $\neg \mathsf{Bad}_{\mathrm{perm}}$, $F$ is a random function on contexts and bare-TreeWrap lemmas are interpreted
in the same experiment. Therefore, $\Pr[\mathsf{Bad}_{\mathrm{perm}}]$ is charged once
as $\varepsilon_{\mathrm{indiff}}$; no second independent indifferentiability term is added.

#### 6.5.1 IND-CPA (nonce-respecting)

Under fresh nonces per encryption query, confidentiality follows from bare TreeWrap pseudorandom keystream behavior
(Lemmas 1–3), plus the context-key collision term from §6.4:

$$
\varepsilon_{\mathrm{ind-cpa}} \le \varepsilon_{\mathrm{indiff}} + \varepsilon_{\mathrm{ctx-coll}}.
$$

#### 6.5.2 INT-CTXT

Across $S$ decryption/verification forgery attempts on new ciphertexts in one security experiment (possibly across
multiple contexts), each attempt must guess a $\tau$-byte tag:

$$
\varepsilon_{\mathrm{int-ctxt}} \le \varepsilon_{\mathrm{indiff}} + \frac{S}{2^{8\tau}} + \varepsilon_{\mathrm{ctx-coll}}.
$$

If tags are truncated to $T<\tau$ bytes, replace $S/2^{8\tau}$ with $S/2^{8T}$.

#### 6.5.3 IND-CCA2 (nonce-respecting)

Standard EtM reduction gives:

$$
\varepsilon_{\mathrm{ind-cca2}} \le \varepsilon_{\mathrm{indiff}} + \frac{S}{2^{8\tau}} + \varepsilon_{\mathrm{ctx-coll}}.
$$

The proof uses nonce-respecting IND-CPA plus decryption-failure indistinguishability from random tag guessing. Nonce
reuse for the same $(K,N,AD)$ is out of scope for this claim and breaks standard deterministic-encapsulation IND-CCA2
formulations.

### 6.6 CMT-4 for TreeWrap-AEAD (fixed master key)

This theorem composes the same §6.4 context-to-key lift with fixed-key committing behavior from bare TreeWrap. It is a
composition argument over published sponge/duplex and TurboSHAKE/KangarooTwelve analyses, not a new standalone
primitive-security theorem (see §8: Bellare-Hoang for CMT-4 and the cited Keccak/TurboSHAKE/KangarooTwelve analyses).

**Game.** Sample one secret master key $K$ once and give the adversary encryption-oracle access under $K$. The adversary
outputs two distinct tuples $(N,AD,M) \neq (N',AD',M')$ such
that $\mathrm{Encrypt}(K,N,AD,M) = \mathrm{Encrypt}(K,N',AD',M')$.

Split into two exhaustive cases.

#### Case A: Different AEAD contexts

$(N,AD) \neq (N',AD')$.

Distinct AEAD contexts under fixed $K$ imply distinct encoded context strings $X \neq X'$. In $\mathsf{G}_1$, either:

- $R(X)=R(X')$ (context-key collision event, bounded by $\varepsilon_{\mathrm{ctx-coll}}$), or
- $R(X)\neq R(X')$, and an equal-output event is upper-bounded by the $Q$-trial birthday term over $\tau$-byte tags
  (since $\Pr[\texttt{ct||tag collision}] \le \Pr[\texttt{tag collision}]$).

#### Case B: Same AEAD context, different messages

Same $(N,AD)$ implies the same derived key (for fixed master key $K$). If $M \neq M'$, then by Lemma 3 (fixed-key
bijection), ciphertexts differ, so the full AEAD outputs `ct || tag` cannot be equal.

Combining both cases:

$$
\varepsilon_{\mathrm{cmt4}} \le \varepsilon_{\mathrm{indiff}} + \frac{Q^2}{2^{8\tau+1}} + \varepsilon_{\mathrm{ctx-coll}}.
$$

Here $Q$ is the total number of compared AEAD outputs in the experiment (oracle outputs and final compared outputs).

For $\tau = C = 32$, both birthday denominators are $2^{257}$.

### 6.7 Caller Obligations for Bare TreeWrap

`TreeWrap-AEAD` enforces nonce/key derivation and verification behavior. Bare TreeWrap exposes raw `(output, tag)` and
therefore requires caller discipline.

| Property target              | Caller obligation                                                   |
|------------------------------|---------------------------------------------------------------------|
| IND-CPA-like confidentiality | Ensure key uniqueness per `EncryptAndMAC` invocation.               |
| INT-CTXT-like authenticity   | Compare tags in constant time; reject plaintext on mismatch.        |
| IND-CCA2-like behavior       | Do not release/act on plaintext before successful tag verification. |
| CMT-4                        | No extra runtime check required beyond the algorithm definition.    |

For wrapped deployments, use the §6.6 decomposition directly: confidentiality/authenticity and CMT-4 share the same
single global model term, and CMT-4 additionally includes the explicit context-to-`K_tw` collision term.

### 6.8 Chunk Reordering, Length Changes, and Empty Input

- Reordering chunks changes leaf-index binding (`key || LEU64(index)`), so recomputed tag changes.
- Truncation/extension changes chunk count $n$, changing `right_encode(n)` in final accumulation input.
- Empty plaintext uses $n=1$: one leaf with `single_node_tag()`, no final accumulation node.

### 6.9 Side Channels

Implementations MUST be constant-time with respect to secret-dependent control flow and memory access.

- No lookup tables indexed by secret state bytes.
- Tag verification MUST use constant-time equality.
- Partial-block logic may branch on public length, not on secret data.

### 6.10 Operational Usage Limits (Normative)

To claim the 128-bit security target in this specification, deployments MUST enforce per-master-key usage limits (a key
epoch) and rotate to a fresh master key before exceeding them.

Implementations MUST maintain the following per-key-epoch counters:

- $q_{\mathrm{enc}}$: number of encryption invocations.
- $\sigma_{\mathrm{total}} = \sigma_{\mathrm{treewrap-aead}} + \sigma_{\mathrm{other\ keccak\ uses\ in\ scope}}$.
- $q_{\mathrm{nonce}}$: number of random nonces used (only for random-nonce deployments).
- $S$: number of failed decryption/verification attempts processed (forgery attempts).

Required baseline profile (MUST):

- Enforce $\sigma_{\mathrm{total}} \le 2^{60}$.
- Define and enforce an encryption-invocation cap $q_{\mathrm{enc}} \le q_{\mathrm{enc,cap}}$ per key epoch.
- Enforce nonce uniqueness per key epoch (deterministic nonces such as counters/sequences are RECOMMENDED; random-nonce
  deployments SHOULD use a large nonce space, e.g., 192 or 256 bits).
- For deterministic nonces, choose $q_{\mathrm{enc,cap}}$ so nonce values cannot wrap or repeat within the epoch.
- If random nonces are used, additionally enforce
  $q_{\mathrm{nonce}}(q_{\mathrm{nonce}}-1)/2^{b+1} \le p_{\mathrm{nonce}}$ for chosen nonce-collision target
  $p_{\mathrm{nonce}}$.
- Define and enforce a failed-verification budget $S_{\mathrm{cap}}$ per key epoch. If $S > S_{\mathrm{cap}}$,
  implementations MUST stop accepting further decryption attempts for that epoch and rotate to a fresh key epoch before
  resuming.
- On any cap exceedance (workload, invocation, nonce, or failed-verification policy), implementations MUST rotate to a
  fresh key epoch before any further encryption.

Expert profile (non-normative): deployments with stronger review/monitoring may choose workload caps above $2^{60}$, up
to $2^{64}$, using the same counter model.

Security interpretation remains the §6 bound family evaluated at observed counters, with adversary offline budget
parameter $t$ treated as an analysis parameter (not an operationally measurable quantity).

Appendix C remains non-normative operational guidance for instrumentation and budgeting workflows.

### 6.11 Implementation Design Callouts (Non-Normative)

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
- **Keep domain bytes and index mapping exact.** `0x60`–`0x65` constants and `key || LEU64(index)` binding are
  structural for interoperability and security analysis.
- **Treat reference code as correctness-first.** For production throughput, avoid repeated byte-string concatenation
  patterns when constructing final-node inputs.

## 7. Comparison with Traditional AEAD

TreeWrap differs from traditional AEAD in several respects. This document defines a concrete AEAD construction
(TreeWrap-AEAD, §5.2) for security analysis purposes, but the core primitive remains a bare
`EncryptAndMAC`/`DecryptAndMAC` interface.

**No internal tag verification.** Traditional AEAD schemes (AES-GCM, ChaCha20-Poly1305, etc.) perform tag comparison
inside the `Open`/`Decrypt` function and return ⊥ on failure, ensuring plaintext is never released before
authentication. TreeWrap's `DecryptAndMAC` always returns both plaintext and tag, leaving verification to the caller.
This supports protocol frameworks that need the tag for transcript state advancement regardless of verification outcome.

**Nonce-free bare primitive.** The bare TreeWrap primitive takes only a key and plaintext. It does not accept a nonce or
associated data. Nonce handling is the KDF's responsibility: `TreeWrap-AEAD` (§5.2) accepts nonces, but they are
consumed by the concrete TurboSHAKE128-based KDF to derive a unique TreeWrap key, not passed to TreeWrap itself. The key
MUST be pseudorandom (indistinguishable from uniform) and unique per invocation (see §5.1).

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs — they prove authenticity but are not
necessarily pseudorandom. TreeWrap's tag is a full PRF: under a random key, the tag is indistinguishable from a random
string (§6.3.1). This stronger property supports protocols that absorb the tag into ongoing state.

### 7.1. Usage Limits

Direct volume comparison with assumptions: $p = 2^{-50}$, 1500-byte messages, TreeWrap-AEAD cost $\approx 11$ Keccak-p
calls/message (1 KDF + 10 leaf calls), per-key accounting (single key / key epoch), and a 128-bit TreeWrap nonce profile
for random-nonce deployments. These figures are conditional on the §6 ideal-permutation assumption for
Keccak-p[1600,12].

| Scheme        | Limit type       | Approx protected volume |
|---------------|------------------|-------------------------|
| AES-128-GCM   | per key          | $\approx 2^{13.1}$ GiB  |
| TreeWrap-AEAD | proof bound only | $\approx 2^{80.6}$ GiB  |

The AES-128-GCM figure is from Günther, Thomson, and Wood (Table 2) converted to GiB. The TreeWrap figure is the
corresponding conversion of the §6 bound under the assumptions above. It is not the practical limit when random nonces
are used; practical limits follow the minimum rule below.

For deployment planning, use:

$$
\text{practical per-key volume} = \min(\text{proof-bound volume},\ \text{nonce-collision-limited volume}).
$$

With uniformly random 128-bit nonces and collision target $p = 2^{-50}$, the nonce budget is approximately
$q_{\mathrm{nonce}} \lesssim 2^{39.5}$ encryptions per key (birthday approximation), so at 1500 bytes/message:

$$
\text{nonce-collision-limited volume} \approx 2^{39.5} \cdot 1500\ \text{bytes} \approx 2^{20.1}\ \text{GiB}.
$$

TreeWrap supports longer nonces (e.g., 192 or 256 bits) with the same construction; this increases the random-nonce
collision budget in the usual birthday way.

## 8. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop, 2007. Establishes
  the flat sponge claim (sponge indifferentiability from a random oracle).
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint
  2013/231. Defines the tree hash coding framework used by KangarooTwelve and TreeWrap.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., and Van Keer, R. "TurboSHAKE." IACR ePrint 2023/342.
  Primary specification and design rationale for TurboSHAKE.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., and Van Keer, R. "KangarooTwelve: fast hashing based on
  Keccak-p." IACR ePrint 2016/770. Security and design context for the Sakura-based tree structure.
- Keccak Team. "Third-party cryptanalysis." https://keccak.team/third_party.html. Curated summary table of published
  cryptanalysis results and round counts across Keccak-family modes and raw permutations.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing
  security notion.
- Günther, F., Thomson, M., and Wood, C. A. "Usage Limits on AEAD Algorithms." draft-irtf-cfrg-aead-limits-11. Concrete
  usage limit tables for AES-GCM and ChaCha20-Poly1305; referenced in §7.1.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Duplexing the Sponge: Single-Pass Authenticated Encryption
  and Other Applications." SAC 2011. IACR ePrint 2011/499. Proves that duplex outputs are pseudorandom under the sponge
  indifferentiability assumption (Theorem 1); establishes that all intermediate rate outputs — not just terminal
  squeezes — are covered by the duplex security bound.
- Mennink, B., Reyhanitabar, R., and Vizár, D. "Security of Full-State Keyed Sponge and Duplex: Beyond the Birthday
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

All bare TreeWrap vectors use:

- **Key:** 32 bytes `00 01 02 ... 1f`
- **Plaintext:** `len` bytes `00 01 02 ... (len−1) mod 256`

Ciphertext prefix shows the first `min(32, len)` bytes. Tags are full 32 bytes. All values are hexadecimal.

### 9.1 Empty Plaintext (MAC-only, n = 1)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 0                                                                  |
| ct    | (empty)                                                            |
| tag   | `668f373328d7bb108592d3aaf3dacdabcccff2ca302677c6ea33addf4f72990d` |

### 9.2 One-Byte Plaintext (n = 1)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 1                                                                  |
| ct    | `f1`                                                               |
| tag   | `c04761e374ccb3a926eeabbe49698122b5d72d362deb35c04a22132676309c35` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`8e419b1ad3363b42ebdf788c914c94e826a0d4864b6eb828c33ac460a60f7cee`.

### 9.3 B-Byte Plaintext (exactly one chunk, n = 1)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8192                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `16ca20542882e63361f8dce572834de742e828f3046cdffc90b5b79faa8e86e2` |

Flipping bit 0 of `ct[0]` yields tag
`252c145ed845841ee9156ed46febaf03ad213d727256c761a36db0bf10901ea8`.

### 9.4 B+1-Byte Plaintext (two chunks, minimal second, n = 2)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8193                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `334010388fc60b70a51e9e0f2e83222549e3231153575e27fce16227ea197bb1` |

Flipping bit 0 of `ct[0]` yields tag
`76398352ca9c7594808135f297f085bda06bb1ccd0f328246e22cedc7ecfdf65`.

### 9.5 4B-Byte Plaintext (four full chunks, n = 4)

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

For all bare vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as `EncryptAndMAC`.

### 9.7 TreeWrap-AEAD Vectors

These vectors validate the `treewrap_aead_encrypt` / `treewrap_aead_decrypt` wrapper in §5.2, including SP 800-185
`encode_string` key derivation.

#### 9.7.1 Empty Message

| Field  | Value                                                              |
|--------|--------------------------------------------------------------------|
| K      | 32 bytes `00 01 02 ... 1f`                                         |
| N      | 12 bytes `00 01 02 ... 0b`                                         |
| AD     | (empty)                                                            |
| M len  | 0                                                                  |
| ct‖tag | `25b1c33a42d3dd8546c0de7df2edc6d3fa1d39b4e1ee9696b6a046c6f853d54e` |

`treewrap_aead_decrypt(K, N, AD, ct‖tag)` returns the original plaintext. Changing `N`, `AD`, or `tag` causes decryption
to return `None`.

#### 9.7.2 33-Byte Message With 5-Byte AD

| Field  | Value                                                                                                                                |
|--------|--------------------------------------------------------------------------------------------------------------------------------------|
| K      | 32 bytes `00 01 02 ... 1f`                                                                                                           |
| N      | 12 bytes `a0 a1 a2 ... ab`                                                                                                           |
| AD     | 10 11 12 ... 14                                                                                                                      |
| M len  | 33 (`00 01 02 ... mod 256`)                                                                                                          |
| ct‖tag | `d88f1d9d2b6f31316427abef58ef07ef047d4e9d3faec99c677a5b7d895b682fe8b98d90320dd7d3773160424f8b1a7aa4522038c5871e62689cdb90ef8820aa64` |

`treewrap_aead_decrypt(K, N, AD, ct‖tag)` returns the original plaintext. Changing `N`, `AD`, or `tag` causes decryption
to return `None`.

#### 9.7.3 Multi-Chunk Message (8193 Bytes)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| K       | 32 bytes `42 43 44 ... 61`                                         |
| N       | 12 bytes `c0 c1 c2 ... cb`                                         |
| AD      | 00 01 02 ... 10                                                    |
| M len   | 8193 (`00 01 02 ... mod 256`)                                      |
| ct[:32] | `f5774bff15f14fd3b08bc8e48c63cad9d84b348b1c3097551db20dce21b0b36d` |
| tag     | `ab269d885fea7d1e55e7872103fc4d876237c24c98a45d338473ca60324fc04f` |

`treewrap_aead_decrypt(K, N, AD, ct‖tag)` returns the original plaintext.
Changing `N`, `AD`, or `tag` causes decryption to return `None`.

## Appendix A. Exact Per-Query σ Formula

For a single `TreeWrap-AEAD` query on a message of length $L$ bytes with
$n = \max(1, \lceil L / B \rceil)$ chunks of sizes $\ell_0, \ldots, \ell_{n-1}$, the per-query contribution to
$\sigma$ is:

$$\sigma_{\mathrm{query}} = \underbrace{\left(\left\lfloor \frac{|\mathit{kdf\_input}|}{R} \right\rfloor + 1\right)}_{\text{KDF}} + \underbrace{\sum_{i=0}^{n-1}\left(1 + \max\!\left(1,\, \left\lceil \frac{\ell_i}{R-1} \right\rceil\right)\right)}_{\text{leaves}} + \underbrace{\mathbb{1}_{n>1} \cdot \left(\left\lfloor \frac{|\mathit{final\_input}|}{R} \right\rfloor + 1\right)}_{\text{tag accumulation}}$$

where:

- **KDF term.** $|\mathit{kdf\_input}|$ is the byte length of
  `encode_string(K) || encode_string(N) || encode_string(AD)`.
  Each `encode_string` contributes `left_encode(8|x|)` (2–3 bytes for practical lengths) plus the field itself. For a
  32-byte key, 12-byte nonce, and empty AD, $|\mathit{kdf\_input}| = (3+32) + (2+12) + (2+0) = 51$ bytes, giving
  $\lfloor 51 / 168 \rfloor + 1 = 1$ Keccak-p call.
  (The `+1` accounts for TurboSHAKE's pad+permute step even when the absorb phase ends exactly on a rate boundary.)
- **Leaf term.** Each leaf costs $1$ (init `pad_permute`) $+$ $\max(1, \lceil \ell_i / (R-1) \rceil)$ (ciphertext
  block permutations and the final squeeze — at least 1 even for empty chunks). For a full $B = 8192$-byte chunk:
  $1 + \lceil 8192 / 167 \rceil = 1 + 50 = 51$.
- **Tag accumulation term.** Present only when $n > 1$. $|\mathit{final\_input}| = 8 + nC +
  |\mathrm{right\_encode}(n)| + 2$ bytes. For $n = 2$: $|final\_input| = 8 + 64 + 2 + 2 = 76$ bytes, giving
  $\lfloor 76 / 168 \rfloor + 1 = 1$.

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

`left_encode` and `encode_string` follow NIST SP 800-185. `right_encode` follows the KangarooTwelve
convention (RFC 9861): for $x = 0$ it returns a single `0x00` byte rather than `0x00 0x01`. TreeWrap
only calls `right_encode` with $n \geq 2$, so the difference is unreachable in practice.

```python
def right_encode(x: int) -> bytes:
    """Big-endian, no leading zeros, followed by byte count (KangarooTwelve convention)."""
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

## Appendix C. Deployment Budgeting Across TreeWrap, TurboSHAKE, and KangarooTwelve (Non-Normative)

This appendix is operational guidance for practitioners combining multiple Keccak-based components in one system.
It is not part of the normative algorithm definition.

### C.1 Why this matters

The security bounds in §6 are driven by the total Keccak-p call budget term:

$$
\varepsilon_{\mathrm{indiff}} = \frac{(\sigma + t)^2}{2^{c+1}}.
$$

When a deployment uses multiple Keccak-based components under related security assumptions, a conservative practice is
to budget their Keccak-p calls together rather than treating each component in isolation.

### C.2 Practitioner workflow

For a chosen operational window (for example, per key epoch, per process lifetime, or per day), define:

```text
sigma_total = sigma_treewrap + sigma_turboshake + sigma_k12 + sigma_other_keccak
```

where each term is the count of online Keccak-p[1600,12] calls made by that component in the window.
This is the same $\sigma_{\mathrm{total}}$ counter model used normatively in §6.10.

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

- TreeWrap calls and message sizes (convert via Appendix A’s per-query formula),
- TurboSHAKE/KangarooTwelve calls and absorbed lengths,
- key/epoch identifiers to support budget resets at rotation boundaries.

This enables straightforward capacity planning and post-incident verification of whether configured limits were
exceeded.

### C.4 Practical default

For most deployments, this budget is generous. The value of tracking it is not that limits are usually tight, but that:

- the system has an explicit, reviewable safety margin,
- key-rotation policy is tied to measurable cryptographic workload,
- mixed-component deployments avoid silent overuse assumptions.
