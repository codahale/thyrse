# TreeWrap: Tree-Parallel Stream Cipher and MAC

**Status:** Draft
**Version:** 0.4
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

A leaf cipher implements the DWrap mode (using the overwrite duplex optimization) over a standard Keccak sponge, using the same permutation and rate/capacity parameters as TurboSHAKE128. It uses domain separation byte `0x60` for intermediate blocks and `0x61` for the final block.

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

After `init`, the cipher has absorbed the key and index and is ready for encryption.

**encrypt(P) → C:** For each plaintext byte `Pⱼ`:  
&emsp; `Cⱼ ← Pⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more plaintext remains, call `pad_permute(0x60)`.  
Return concatenated ciphertext bytes.

**decrypt(C) → P:** For each ciphertext byte `Cⱼ`:  
&emsp; `Pⱼ ← Cⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more ciphertext remains, call `pad_permute(0x60)`.  
Return concatenated plaintext bytes.

Note: both encrypt and decrypt overwrite the rate with ciphertext. This ensures the state evolution is identical regardless of direction, which is required for EncryptAndMAC/DecryptAndMAC consistency.

**chain_value() → cv:**  
&emsp; Call `pad_permute(0x61)`.  
&emsp; Output C bytes: for each byte, output `S[pos]` and increment `pos`. When `pos` reaches R−1 and more output remains, call `pad_permute(0x61)`.

`chain_value()` always begins with `pad_permute(0x61)` to ensure all encrypted data is fully mixed and securely domain-separated from intermediate permutations before the chain value is derived.

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
&emsp; `tag ← TurboSHAKE128(final_input, 0x62, C)`

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
&emsp; `tag ← TurboSHAKE128(final_input, 0x62, C)`

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

The argument follows from the same monolithic reduction as §6.2. After replacing all sponge evaluations with random oracle evaluations, each leaf's chain value is an independent random oracle output (distinct inputs due to leaf indices). The tag is $\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x62}, C)$ where $\mathit{final\_input}$ is a deterministic, injective encoding of the chain values. Domain byte 0x62 separates the tag computation from the leaf ciphers (0x60/0x61), so the tag evaluation is an independent random oracle call on a pseudorandom input, producing a pseudorandom output.

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

The argument is as follows. The tag is a collision-resistant function of (key, ciphertext) (§6.4). Since the encryption within each leaf is invertible for a given key (the overwrite duplex encrypt/decrypt operations are inverses), committing to (key, ciphertext) is equivalent to committing to (key, plaintext). An adversary who produces two distinct tuples $(K, P)$ and $(K', P')$ that yield the same (ciphertext, tag) has found a collision in the tag computation.

This committing property is inherent to the construction — it does not require any additional processing or a second pass over the data, unlike generic CMT-4 transforms applied to non-committing AE schemes.

### 6.6 Forgery Resistance

An adversary who does not know the key and attempts to produce a valid (ciphertext, tag) pair succeeds with probability at most:

$$\varepsilon_{\mathrm{forge}} \leq \frac{S}{2^{8C}} = \frac{S}{2^{256}}$$

for $S$ forgery attempts against the full $C$-byte tag. When the caller truncates the tag to $T$ bytes (as in Thyrse's Seal/Open), the forgery bound becomes $S / 2^{8T}$.

Note that forgery resistance is a consequence of tag PRF security (§6.3): the tag on any ciphertext the adversary has not queried is indistinguishable from random, and guessing a random $C$-byte value succeeds with probability $1 / 2^{8C}$.

### 6.7 Chunk Reordering

Each leaf is initialized with `key ‖ [index]₆₄LE`, binding it to its position. Reordering ciphertext chunks changes which leaf decrypts which data, producing different chain values and a different tag. Additionally, since leaf indices are bound at initialization, an attacker cannot cause chunk $i$'s ciphertext to be decrypted as chunk $j$ — the decryption will produce garbage and the chain value will not match.

### 6.8 Empty Plaintext

When plaintext is empty, a single leaf is still created. The chain value is derived from the cipher state after `init` (with a `pad_permute` but no encrypt calls). The final node input is `cv[0] ‖ 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ‖ 0x00 ‖ 0xFF 0xFF`, producing a valid tag that authenticates the key. This ensures DecryptAndMAC with an empty ciphertext computes the same tag as EncryptAndMAC with an empty plaintext.

### 6.9 Tag Accumulation Structure

Chain values are accumulated using the KangarooTwelve final node structure: `cv[0]` is absorbed as the "first chunk" of the final node, followed by the 8-byte marker `0x03 0x00...`, then chain values `cv[1]` through `cv[n−1]` as "leaf" contributions, followed by `length_encode(n−1)` and the terminator `0xFF 0xFF`. This is processed by TurboSHAKE128 with domain separation byte 0x62, separating TreeWrap tag computation from both KT128 hashing (0x07) and TreeWrap leaf ciphers (0x60/0x61).

The structure is unambiguous: chain values are fixed-size ($C$ bytes each), `length_encode` encodes the number of leaf chain values, and the terminator marks the end. The number of chunks is determined by the ciphertext length, which is assumed to be public.

### 6.10 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext values. The chunk index is not secret and does not require side-channel protection.

### 6.11 Concrete Security Reduction

Each leaf cipher is an overwrite duplex operating on the Keccak-p[1600,12] permutation with capacity $c = 256$ bits. The security argument proceeds in two steps: a syntactic rewriting that is information-theoretic, followed by a single application of the sponge indifferentiability theorem.

**Step 1: Overwrite duplex equivalence.** Each leaf cipher implements DWrap mode over a standard Keccak sponge. It uses standard TurboSHAKE padding, meaning each permutation call within the leaf precisely matches the behavior of a standard TurboSHAKE sponge evaluation. By the overwrite-to-XOR equivalence (Daemen et al., Lemma 2), each leaf's computation can be expressed as a standard $\mathrm{Keccak}[256]$ sponge evaluation on an injective encoding of the leaf's inputs. The injectivity holds because: (a) the ciphertext overwrite is injective for a given keystream, and (b) the distinct domain bytes (0x60 for intermediate blocks, 0x61 for the final block) ensure that the block encoding is injective, eliminating any truncation ambiguities. This step is a syntactic rewriting with no computational cost.

After this rewriting, all computations in a TreeWrap invocation — $n$ leaf sponge evaluations plus one tag accumulation (TurboSHAKE128 with domain byte 0x62) — are standard sponge evaluations on distinct inputs. Leaf inputs differ by index; the tag evaluation is separated by domain byte.

**Step 2: Monolithic indifferentiability reduction.** The sponge indifferentiability theorem replaces all sponge evaluations simultaneously with random oracle evaluations in a single reduction. Under the random oracle, distinct inputs yield independent, uniformly random outputs: all $n$ chain values are simultaneously pseudorandom (independent across leaves due to distinct indices), and the tag is pseudorandom (independent of the leaves due to domain byte 0x62).

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
| tag   | `b97e7c92fa2b21c99e6c5ac2d84851a2d1ad499e908966700cab0bd65dbd7446` |

DecryptAndMAC with the same key and empty ciphertext produces the same tag.

### 9.2 One-Byte Plaintext ($n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 1                                                                  |
| ct    | `f1`                                                               |
| tag   | `6fd28612971748f9dc92a521176ae87ab3ee9d5ab933b0a996c9cd4e7f68399d` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`ea8f064c8279832bb0b4807c86249c24f7dcc5cefa1753fcc83b99ba9fd4411c`.

### 9.3 B-Byte Plaintext (exactly one chunk, $n = 1$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8192                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `92064ea90b27e976db3c26715241a0cd447a885bc0f2a62989df5712189b411c` |

Flipping bit 0 of `ct[0]` yields tag
`9f7ac08d739f2240ff1ca9a8e71f8fddfe62d72d1f1e0d37f5dd4bab41125c19`.

### 9.4 B+1-Byte Plaintext (two chunks, minimal second, $n = 2$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8193                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `5c2f1854515fa7b8d991d33fbc656fd3a4c2430cdc848f19bf1bab897980e977` |

Flipping bit 0 of `ct[0]` yields tag
`a11efae07fce8d7171c6578f734e0ff2b08b4a4dd51284a8f45f4e64e4461ad4`.

### 9.5 4B-Byte Plaintext (four full chunks, $n = 4$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 32768                                                              |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `38a1526fa79bcebeba91cbd04ca1bf09beb524918956cda9ce470a6f6b61d717` |

Flipping bit 0 of `ct[0]` yields tag
`7dc8ebe96eed2005977ee41115a9cfa16644e5ebdd9eefcc162186f8b3312ea8`.

Swapping chunks 0 and 1 (bytes 0–8191 and 8192–16383) yields tag
`4fb8bb5abd9cd81ca661d0092b69f57691374034f5ec03f57cd61c2fd8cc8ff9`.

### 9.6 Round-Trip Consistency

For all vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as `EncryptAndMAC`.
