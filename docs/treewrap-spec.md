# TreeWrap: Tree-Parallel Stream Cipher and MAC

**Status:** Draft
**Version:** 0.5
**Date:** 2026-02-28
**Security Target:** 128-bit

## 1. Introduction

TreeWrap is a deterministic stream cipher with a MAC tag, using a tree-parallel topology based on KangarooTwelve to enable SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf operates as a DWrap mode instance over a standard Keccak sponge (using the overwrite duplex optimization), and leaf chain values are accumulated into a single MAC tag via TurboSHAKE128.

TreeWrap is not an AEAD scheme. It does not perform tag verification internally. Instead, it exposes two operations — **EncryptAndMAC** and **DecryptAndMAC** — which both return the computed tag to the caller. The caller is responsible for tag comparison, transmission, and any policy decisions around verification failure. This design supports protocol frameworks like Thyrse that need to absorb the tag into ongoing state regardless of verification outcome, or that authenticate ciphertext through external mechanisms such as signatures.

TreeWrap is a pure function with no internal state. Key uniqueness and associated data are managed by the caller.

## 2. Parameters

| Symbol | Value | Description |
|--------|-------|-------------|
| f | Keccak-p[1600,12] | Underlying permutation (1600-bit state, 12 rounds) |
| R | 168 | Rate (bytes) |
| C | 32 | Capacity (bytes); key, chain value, and tag size |
| B | 8192 | Chunk size (bytes), matching KangarooTwelve |

## 3. Dependencies

**TurboSHAKE128(M, D, $\ell$):** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01–0x7F), and an output length $\ell$ in bytes.

## 4. Leaf Cipher

A leaf cipher implements the DWrap mode (using the overwrite duplex optimization) over a standard Keccak sponge, using the same permutation and rate/capacity parameters as TurboSHAKE128. It uses four domain separation bytes: `0x60` for init (key/index absorption), `0x61` for intermediate encrypt/decrypt blocks, `0x62` for the final block (chain value derivation), and `0x63` for tag accumulation.

The overwrite duplex differs from the traditional XOR-absorb duplex (SpongeWrap) in that the encrypt operation overwrites the rate with ciphertext rather than XORing plaintext into it. This has two consequences: first, it enables a clean security reduction to the standard Keccak sponge via the equivalence shown by Daemen et al. for the overwrite duplex construction; second, for full-rate blocks, overwrite is faster than XOR on most architectures (write-only vs. read-XOR-write).

A leaf cipher consists of a 200-byte state `S`, initialized to all zeros, and a rate index `pos`, initialized to zero.

**`pad_permute(domain_byte)`:**  
&emsp; `S[pos] ^= domain_byte`  
&emsp; `S[R-1] ^= 0x80`  
&emsp; `S ← f(S)`  
&emsp; `pos ← 0`

Note: This matches standard TurboSHAKE padding, where the domain byte includes the first bit of the `pad10*1` sequence.

**init(key, index):**  
&emsp; For each byte of `key ‖ [index]₆₄LE`, XOR it into `S[pos]` and increment `pos`. When `pos` reaches R−1 and more input remains, call `pad_permute(0x60)`.
&emsp; Call `pad_permute(0x60)`.

Note: Init uses domain byte `0x60`, distinct from the intermediate encrypt/decrypt byte `0x61`. This ensures the key absorption block is domain-separated from ciphertext blocks.

After `init`, the cipher has absorbed the key and index and is ready for encryption.

**encrypt(P) → C:** For each plaintext byte `Pⱼ`:
&emsp; `Cⱼ ← Pⱼ ⊕ S[pos]`
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)
&emsp; Increment `pos`. When `pos` reaches R−1 and more plaintext remains, call `pad_permute(0x61)`.  
Return concatenated ciphertext bytes.

**decrypt(C) → P:** For each ciphertext byte `Cⱼ`:
&emsp; `Pⱼ ← Cⱼ ⊕ S[pos]`
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)
&emsp; Increment `pos`. When `pos` reaches R−1 and more ciphertext remains, call `pad_permute(0x61)`.  
Return concatenated plaintext bytes.

Note: both encrypt and decrypt overwrite the rate with ciphertext. This ensures the state evolution is identical regardless of direction, which is required for EncryptAndMAC/DecryptAndMAC consistency.

**chain_value() → cv:**
&emsp; Call `pad_permute(0x62)`.
&emsp; Output C bytes: for each byte, output `S[pos]` and increment `pos`. When `pos` reaches R−1 and more output remains, call `pad_permute(0x62)`.

`chain_value()` always begins with `pad_permute(0x62)` to ensure all encrypted data is fully mixed and securely domain-separated from intermediate permutations before the chain value is derived.

## 5. TreeWrap

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.
- `length_encode(x)`: The encoding used by KangarooTwelve: `x` as a big-endian byte string with no leading zeros, followed by a single byte indicating the length of that byte string. `length_encode(0)` is `0x00`.

### 5.1 EncryptAndMAC

**TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)**

*Inputs:*
- `key`: A C-byte key. MUST be pseudorandom and unique per invocation (see §6.1).
- `plaintext`: Plaintext of any length (may be empty).

*Outputs:*
- `ciphertext`: Same length as `plaintext`.
- `tag`: A C-byte MAC tag.

*Procedure:*

Partition `plaintext` into $n = \max(1, \lceil\mathit{len}(\mathit{plaintext}) / B\rceil)$ chunks. Chunk $i$ (0-indexed) has size $\ell_i = \min(B,\, \mathit{len}(\mathit{plaintext}) - i \cdot B)$. If plaintext is empty, $n = 1$ and the single chunk is empty.

For each chunk `i`:  
&emsp; Create a leaf cipher `L`.  
&emsp; `L.init(key, i)`  
&emsp; `ciphertext[i] ← L.encrypt(plaintext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the tag using the KangarooTwelve final node structure:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `tag ← TurboSHAKE128(final_input, 0x63, C)`

When `n = 1`, the final input reduces to `cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ length_encode(0) ‖ 0xFF 0xFF`.

Return `(ciphertext[0] ‖ ... ‖ ciphertext[n−1], tag)`.

All leaf operations are independent and may execute in parallel. Tag computation begins as soon as all chain values are available.

### 5.2 DecryptAndMAC

**TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)**

*Inputs:*
- `key`: A C-byte key.
- `ciphertext`: Ciphertext of any length (may be empty).

*Outputs:*
- `plaintext`: Same length as `ciphertext`.
- `tag`: A C-byte MAC tag.

*Procedure:*

Partition `ciphertext` into chunks identically to EncryptAndMAC.

For each chunk `i`:  
&emsp; Create a leaf cipher `L`.  
&emsp; `L.init(key, i)`  
&emsp; `plaintext[i] ← L.decrypt(ciphertext_chunk[i])`  
&emsp; `cv[i] ← L.chain_value()`

Compute the tag using the same final node structure as EncryptAndMAC:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`  
&emsp; `final_input ← final_input ‖ cv[1] ‖ ... ‖ cv[n−1]`  
&emsp; `final_input ← final_input ‖ length_encode(n−1)`  
&emsp; `final_input ← final_input ‖ 0xFF 0xFF`  
&emsp; `tag ← TurboSHAKE128(final_input, 0x63, C)`

Return `(plaintext[0] ‖ ... ‖ plaintext[n−1], tag)`.

The caller is responsible for comparing the returned tag against an expected value. TreeWrap does not perform tag verification.

## 6. Security Properties

TreeWrap provides the following security properties under the assumptions stated in §6.1 and that Keccak-p[1600,12] is indistinguishable from a random permutation. Each property reduces to the Keccak sponge claim via TurboSHAKE128's indifferentiability from a random oracle.

### 6.1 Key Requirements

TreeWrap requires two properties of its key:

1. **Pseudorandomness.** The key MUST be indistinguishable from a uniformly random C-byte string to any adversary. All security properties in §6.2–6.6 are proved under the assumption of a uniformly random key and degrade proportionally to the adversary's advantage in distinguishing the key from random.

2. **Uniqueness.** The key MUST NOT be reused across invocations. TreeWrap is a deterministic algorithm with no nonce input. Encrypting two different plaintexts with the same key produces ciphertext XOR differences equal to the plaintext XOR differences, fully compromising confidentiality.

When used within a protocol framework, both properties are typically ensured by deriving the key from transcript state (via a PRF such as TurboSHAKE128) that includes a nonce or counter. The pseudorandomness of the derived key then reduces to the PRF security of the derivation function.

### 6.2 Confidentiality (IND$ for a Single Invocation)

Under a uniformly random key, TreeWrap ciphertext is indistinguishable from a random string of the same length. The argument follows from the monolithic sponge indifferentiability reduction (§6.11):

By the overwrite duplex equivalence (Daemen et al.), each leaf's computation can be expressed as a standard sponge evaluation on an injective encoding of its inputs. The sponge indifferentiability theorem then replaces all sponge evaluations — across all $n$ leaves simultaneously — with random oracle evaluations in a single reduction. Under the random oracle, each leaf receives a distinct input (due to the index), producing independent pseudorandom keystreams. The ciphertext is `plaintext ⊕ keystream` for each leaf independently, and is therefore indistinguishable from random.

The IND$ advantage is bounded by:

$$\varepsilon_{\mathrm{ind\$}} \leq \frac{(\sigma + t)^2}{2^{c+1}}$$

where:
- $\sigma$ is the total online data complexity across all sponge evaluations in the invocation (all leaves combined), measured in Keccak-p blocks,
- $t$ is the adversary's total offline computational complexity, measured in Keccak-p evaluations, and
- $c = 256$.

The number of leaves does not appear as a separate factor because the indifferentiability reduction handles all sponge evaluations at once; the online queries from all leaves are already counted in $\sigma$.

### 6.3 Tag PRF Security

Under a uniformly random key, the TreeWrap tag is a pseudorandom function of the ciphertext. Specifically, for any fixed ciphertext, the tag output of EncryptAndMAC (or DecryptAndMAC) is indistinguishable from a uniformly random $C$-byte string.

The argument follows from the same monolithic reduction as §6.2. After replacing all sponge evaluations with random oracle evaluations, each leaf's chain value is an independent random oracle output (distinct inputs due to leaf indices). The tag is $\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x63}, C)$ where $\mathit{final\_input}$ is a deterministic, injective encoding of the chain values. Domain byte 0x63 separates the tag computation from the leaf ciphers (0x60–0x62), so the tag evaluation is an independent random oracle call on a pseudorandom input, producing a pseudorandom output.

The tag PRF advantage shares the same bound as IND$:

$$\varepsilon_{\mathrm{prf}} \leq \frac{(\sigma + t)^2}{2^{c+1}}$$

The tag accumulation does not introduce an additional term because it is covered by the same indifferentiability reduction — the TurboSHAKE128 tag evaluation is simply one more sponge call included in the total query count $\sigma$.

This property is required by Thyrse (§13.4 of the Thyrse specification) to ensure that absorbing a TreeWrap tag into the protocol transcript does not compromise the independence of the chain value derived from the same transcript instance.

### 6.4 Tag Collision Resistance

For any two distinct (key, ciphertext) pairs, the probability that EncryptAndMAC (or DecryptAndMAC) produces the same tag is bounded by the collision resistance of TurboSHAKE128:

$$\varepsilon_{\mathrm{coll}} \leq \frac{(\sigma + t)^2}{2^{c+1}}$$

This is because distinct (key, ciphertext) pairs produce distinct sequences of leaf inputs (key, index, ciphertext\_chunk). The leaf cipher's injective encoding ensures distinct sponge inputs, producing distinct chain values (except with probability bounded by the sponge claim). Distinct chain value sequences produce distinct $\mathit{final\_input}$ values (the encoding is injective). Distinct inputs to TurboSHAKE128 collide with probability bounded by the sponge claim.

### 6.5 Committing Security (CMT-4)

TreeWrap provides CMT-4 committing security: the ciphertext and tag together commit to the key and plaintext. This is the strongest committing security notion defined by Bellare and Hoang.

Suppose an adversary produces two distinct tuples $(K, P)$ and $(K', P')$ that yield the same $(C, T)$. There are two cases:

1. **Same key** ($K = K'$). Since $(K, P) \neq (K', P')$, we have $P \neq P'$. But encryption is a bijection for a fixed key (the overwrite duplex encrypt/decrypt operations are inverses), so distinct plaintexts produce distinct ciphertexts: $C \neq C'$. This contradicts $C = C'$.

2. **Different keys** ($K \neq K'$). The pairs $(K, C)$ and $(K', C)$ are distinct (they differ in the key). By tag collision resistance (§6.4), distinct (key, ciphertext) pairs produce distinct tags except with probability $\varepsilon_{\mathrm{coll}}$. This contradicts $T = T'$ except with negligible probability.

In both cases the adversary has either derived a contradiction or broken tag collision resistance. The CMT-4 advantage is therefore bounded by $\varepsilon_{\mathrm{coll}}$.

This committing property is inherent to the construction — it does not require any additional processing or a second pass over the data, unlike generic CMT-4 transforms applied to non-committing AE schemes.

### 6.6 Forgery Resistance

An adversary who does not know the key and attempts to produce a valid (ciphertext, tag) pair succeeds with probability at most:

$$\varepsilon_{\mathrm{forge}} \leq \frac{S}{2^{8C}} + \varepsilon_{\mathrm{prf}} \leq \frac{S}{2^{256}} + \frac{(\sigma + t)^2}{2^{c+1}}$$

for $S$ forgery attempts against the full $C$-byte tag. When the caller truncates the tag to $T$ bytes (as in Thyrse's Seal/Open), the guessing probability increases and the bound becomes $S / 2^{8T} + \varepsilon_{\mathrm{prf}}$.

Note that forgery resistance is a consequence of tag PRF security (§6.3): the tag on any ciphertext the adversary has not queried is indistinguishable from random up to the PRF advantage. Guessing a truly random $T$-byte value succeeds with probability $S / 2^{8T}$, and this is additive with the adversary's advantage in breaking the PRF.

**Tag truncation and committing security.** When the caller truncates the tag to $T < C$ bytes, the collision resistance bound (§6.4) degrades from $(\sigma + t)^2 / 2^{c+1}$ to the birthday bound on the truncated tag: $Q^2 / 2^{8T+1}$ for $Q$ distinct (key, ciphertext) evaluations. This weakens the CMT-4 committing property (§6.5), which is bounded by the collision resistance of the truncated tag. For $T = 16$ (128-bit truncated tags), collisions among honest sessions are expected at $Q \approx 2^{64}$. Callers that truncate the tag and rely on committing security must ensure that the total number of invocations remains well below $2^{4T}$.

### 6.7 Chunk Reordering

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes which leaf decrypts which data, producing different chain values and a different tag. Additionally, since leaf indices are bound at initialization, an attacker cannot cause chunk $i$'s ciphertext to be decrypted as chunk $j$ — the decryption will produce garbage and the chain value will not match.

### 6.8 Empty Plaintext

When plaintext is empty, a single leaf is still created. The chain value is derived from the cipher state after `init` (with a `pad_permute` but no encrypt calls). The final node input is `cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ 0x00 ‖ 0xFF 0xFF`, producing a valid tag that authenticates the key. This ensures DecryptAndMAC with an empty ciphertext computes the same tag as EncryptAndMAC with an empty plaintext.

### 6.9 Tag Accumulation Structure

Chain values are accumulated using the Sakura tree hash coding (Guido Bertoni et al., "Sakura: a flexible coding for tree hashing"), the same framing used by KangarooTwelve (RFC 9861). TreeWrap reuses this encoding because its tree topology — a flat single-level tree with the first chunk interleaved into the final node — is identical to KangarooTwelve's.

The final node input is constructed as:

&emsp; `final_input ← cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ cv[1] ‖ ... ‖ cv[n−1] ‖ length_encode(n−1) ‖ 0xFF 0xFF`

The components of this encoding are:

- **`cv[0]`** (32 bytes): The first chunk's chain value, interleaved directly into the final node rather than being processed as a separate inner node.

- **`0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00`** (8 bytes): The Sakura chaining hop indicator. The byte `0x03` (`0b00000011`) encodes two flags: bit 0 signals that inner-node chain values follow, and bit 1 signals a single-level tree (chain values feed directly into the final node without further tree reduction). The seven zero bytes encode default tree parameters (no sub-tree interleaving).

- **`cv[1] ‖ ... ‖ cv[n−1]`**: Chain values from the remaining chunks, produced by independent leaf cipher evaluations.

- **`length_encode(n−1)`**: The number of inner-node chain values, encoded per KangarooTwelve's convention (big-endian with no leading zeros, followed by a byte giving the encoding length).

- **`0xFF 0xFF`**: The Sakura tree hash terminator, signaling the end of the final node input.

This is processed by TurboSHAKE128 with domain separation byte 0x63, separating TreeWrap tag computation from both KT128 hashing (0x07) and TreeWrap leaf ciphers (0x60–0x62).

The encoding is injective: chain values are fixed-size ($C$ bytes each), the chaining hop indicator and terminator are fixed constants, and `length_encode` uniquely determines $n$. The number of chunks is also determined by the ciphertext length, which is assumed to be public.

### 6.10 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext values. The chunk index is not secret and does not require side-channel protection.

### 6.11 Concrete Security Reduction

Each leaf cipher is an overwrite duplex operating on the Keccak-p[1600,12] permutation with capacity $c = 256$ bits. The security argument proceeds in two steps: a syntactic rewriting that is information-theoretic, followed by a single application of the sponge indifferentiability theorem.

**Step 1: Overwrite duplex equivalence.** Each leaf cipher implements DWrap mode over a standard Keccak sponge. By the overwrite-to-XOR equivalence (Daemen et al., Lemma 2), each leaf's computation can be expressed as a standard $\mathrm{Keccak}[256]$ sponge evaluation on an injective encoding of the leaf's inputs. This step is a syntactic rewriting with no computational cost.

The equivalence requires four preconditions, all of which TreeWrap satisfies:

1. **Proper padding rule.** Each `pad_permute` call applies standard TurboSHAKE padding (`pad10*1` with domain byte), meaning each permutation call within the leaf precisely matches the behavior of a standard TurboSHAKE sponge evaluation.

2. **Capacity not directly accessed.** The construction never reads or writes the capacity portion of the state (bytes $R$ through 199). Key and index absorption (`init`), encryption, and decryption all operate on positions 0 through $R - 2$, within the rate. Chain value squeezing reads positions 0 through $C - 1$ after a permutation, which is also within the rate ($C = 32 < R = 168$).

3. **Overwrite restricted to the rate.** During encryption and decryption, the ciphertext overwrite (`S[pos] ← Cⱼ`) operates at positions 0 through $R - 2$, strictly within the outer (rate) portion of the state.

4. **Key absorption via XOR.** The `init` procedure absorbs key and index material by XORing it into the rate, which is standard sponge absorption (not overwrite). The overwrite applies only during encryption/decryption.

The injectivity of the encoding holds because: (a) the ciphertext overwrite is injective for a given keystream, and (b) the distinct domain bytes (0x60 for init, 0x61 for intermediate encrypt/decrypt blocks, 0x62 for the final block) ensure that the block encoding is injective, eliminating any truncation ambiguities.

After this rewriting, all computations in a TreeWrap invocation — $n$ leaf sponge evaluations plus one tag accumulation (TurboSHAKE128 with domain byte 0x63) — are standard sponge evaluations on distinct inputs. Leaf inputs differ by index; the tag evaluation is separated by domain byte.

**Step 2: Monolithic indifferentiability reduction.** The sponge indifferentiability theorem replaces all sponge evaluations simultaneously with random oracle evaluations in a single reduction. Under the random oracle, distinct inputs yield independent, uniformly random outputs: all $n$ chain values are simultaneously pseudorandom (independent across leaves due to distinct indices), and the tag is pseudorandom (independent of the leaves due to domain byte 0x63).

The advantage of this reduction is bounded by:

$$\varepsilon_{\mathrm{treewrap}} \leq \frac{(\sigma + t)^2}{2^{c+1}}$$

where $\sigma$ is the total online data complexity across all sponge evaluations (all leaves and the tag computation combined), measured in Keccak-p blocks, and $t$ is the adversary's total offline computational complexity in Keccak-p evaluations. The number of leaves does not appear as a separate factor — the online queries from all leaves are already counted in $\sigma$, and the indifferentiability theorem handles all sponge evaluations at once rather than requiring a per-leaf hybrid argument.

**Effective security level.** Setting the bound to 1 and solving for the adversary's total budget gives $\sigma + t \leq 2^{(c+1)/2} = 2^{128.5}$. Since $\sigma$ is determined by the message size and is negligible relative to $2^{128}$ for any practical message, the adversary's offline budget is effectively $t \leq 2^{128}$, matching the 128-bit security target regardless of the number of chunks.

**Multi-invocation degradation.** The bounds above are per-invocation. A protocol performing $Q$ invocations under independent pseudorandom keys degrades by an additional union-bound factor: multiply $\varepsilon_{\mathrm{treewrap}}$ by $Q$, or equivalently subtract $\frac{1}{2}\log_2 Q$ bits from the effective security level. Bounding the total degradation is the calling protocol's responsibility.

## 7. Comparison with Traditional AEAD

TreeWrap differs from traditional AEAD in several respects:

**No internal tag verification.** Traditional AEAD schemes (AES-GCM, ChaCha20-Poly1305, etc.) perform tag comparison inside the Open/Decrypt function and return ⊥ on failure, ensuring plaintext is never released before authentication. TreeWrap's DecryptAndMAC always returns both plaintext and tag, leaving verification to the caller. This is intentional: Thyrse needs the tag for transcript state advancement regardless of verification outcome (see Thyrse specification §10.8).

**Deterministic, no nonce input.** TreeWrap takes only a key and plaintext. It does not accept a nonce or associated data. These are Thyrse's responsibility. The key MUST be pseudorandom and unique per invocation (see §6.1).

**Tag is a PRF output, not just a MAC.** Traditional AEAD tags are MACs — they prove authenticity but are not necessarily pseudorandom. TreeWrap's tag is a full PRF: under a random key, the tag is indistinguishable from a random string. This stronger property is required by Thyrse's composition argument.

## 8. References

- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint 2013/231. Defines the tree hash coding framework used by KangarooTwelve and TreeWrap.
- Daemen, J., Hoffert, S., Mella, S., Van Assche, G., and Van Keer, R. "Shaking up authenticated encryption." IACR ePrint 2024/1618. Defines the overwrite duplex (OD) construction and proves its security equivalence to (Turbo)SHAKE.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines the CMT-4 committing security notion.

## 9. Test Vectors

All vectors use the following inputs:
- **Key:** 32 bytes `00 01 02 ... 1f`
- **Plaintext:** `len` bytes `00 01 02 ... (len−1) mod 256`

Ciphertext prefix shows the first min(32, len) bytes. Tags are full 32 bytes. All values are hexadecimal.

### 9.1 Empty Plaintext (MAC-only, $n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 0                                                                  |
| ct    | (empty)                                                            |
| tag   | `d7cac817ce2e43eb21d29a694e21d6d9c6eb6ae8cd5d87d7ae9c382019908e72` |

DecryptAndMAC with the same key and empty ciphertext produces the same tag.

### 9.2 One-Byte Plaintext ($n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 1                                                                  |
| ct    | `f1`                                                               |
| tag   | `0a1aa945e1ae0b95ec57b1155272237b987457df9783a17234331d4c1e21459c` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`81df961a4a2601dcbacca5a5c1ecdc9915829bb84df26020c43262f983f1429d`.

### 9.3 B-Byte Plaintext (exactly one chunk, $n = 1$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8192                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `4580abcfebe3e1ef44c7a823c3c89dea20f5f38172827d5067983edb6bb836ef` |

Flipping bit 0 of `ct[0]` yields tag
`4de1f6f0832316cb08c6d8ddf1dafab0739c6adb31c41a7b2cbec6e5c448571a`.

### 9.4 B+1-Byte Plaintext (two chunks, minimal second, $n = 2$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8193                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `f22ec68d3bd8ff22580e57ad6638f26cd05c73ad8011af0bc55cc1ac51be7cbc` |

Flipping bit 0 of `ct[0]` yields tag
`b3298c953cd18c2cf3a52dca5c68c529a4a120b3f1870f01a33df857fe0bb1c3`.

### 9.5 4B-Byte Plaintext (four full chunks, $n = 4$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 32768                                                              |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `159dd85c118d70fde96e72c62fa02aa10cc9ea9d4e0ca54aff340af92688219e` |

Flipping bit 0 of `ct[0]` yields tag
`676ad27ef0550c4bac2f503bb51cb73961ba267d45715ab9d8825a61b6004077`.

Swapping chunks 0 and 1 (bytes 0–8191 and 8192–16383) yields tag
`322eba113b8894ffa3f13be2f3ce3f5600a4cf3a532b36bf97d7742e9df712ff`.

### 9.6 Round-Trip Consistency

For all vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as `EncryptAndMAC`.
