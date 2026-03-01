# TreeWrap: Tree-Parallel Stream Cipher and MAC

**Status:** Draft
**Version:** 0.3
**Date:** 2026-02-28
**Security Target:** 128-bit

## 1. Introduction

TreeWrap is a deterministic stream cipher with a MAC tag, using a tree-parallel topology based on KangarooTwelve to enable SIMD acceleration (NEON, AVX2, AVX-512) on large inputs. Each leaf operates as an independent overwrite duplex cipher in the style of Daemen et al.'s DWrap mode, and leaf chain values are accumulated into a single MAC tag via TurboSHAKE128.

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

A leaf cipher is an overwrite duplex cipher using the same permutation and rate/capacity parameters as TurboSHAKE128. It uses domain separation byte `0x60` in place of TurboSHAKE128's caller-specified byte.

The overwrite duplex differs from the traditional XOR-absorb duplex (SpongeWrap) in that the encrypt operation overwrites the rate with ciphertext rather than XORing plaintext into it. This has two consequences: first, it enables a clean security reduction to TurboSHAKE128 via the equivalence shown by Daemen et al. for the overwrite duplex construction; second, for full-rate blocks, overwrite is faster than XOR on most architectures (write-only vs. read-XOR-write).

A leaf cipher consists of a 200-byte state `S`, initialized to all zeros, and a rate index `pos`, initialized to zero.

**`pad_permute()`:**  
&emsp; `S[pos] ^= 0x60`  
&emsp; `S[R-1] ^= 0x80`  
&emsp; `S ← f(S)`  
&emsp; `pos ← 0`

**init(key, index):**  
&emsp; For each byte of `key ‖ [index]₆₄LE`, XOR it into `S[pos]` and increment `pos`. When `pos` reaches R−1 and more input remains, call `pad_permute()`.  
&emsp; Call `pad_permute()`.

After `init`, the cipher has absorbed the key and index and is ready for encryption.

**encrypt(P) → C:** For each plaintext byte `Pⱼ`:  
&emsp; `Cⱼ ← Pⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more plaintext remains, call `pad_permute()`.  
Return concatenated ciphertext bytes.

**decrypt(C) → P:** For each ciphertext byte `Cⱼ`:  
&emsp; `Pⱼ ← Cⱼ ⊕ S[pos]`  
&emsp; `S[pos] ← Cⱼ` (overwrite with ciphertext)  
&emsp; Increment `pos`. When `pos` reaches R−1 and more ciphertext remains, call `pad_permute()`.  
Return concatenated plaintext bytes.

Note: both encrypt and decrypt overwrite the rate with ciphertext. This ensures the state evolution is identical regardless of direction, which is required for EncryptAndMAC/DecryptAndMAC consistency.

**chain_value() → cv:**  
&emsp; Call `pad_permute()`.  
&emsp; Output C bytes: for each byte, output `S[pos]` and increment `pos`. When `pos` reaches R−1 and more output remains, call `pad_permute()`.

`chain_value()` always begins with `pad_permute()` to ensure all encrypted data is fully mixed before the chain value is derived.

## 5. TreeWrap

### Notation

- `‖`: Byte string concatenation.
- `[i]₆₄LE`: The 8-byte little-endian encoding of integer `i`.
- `length_encode(x)`: The encoding used by KangarooTwelve: `x` as a big-endian byte string with no leading zeros, followed by a single byte indicating the length of that byte string. `length_encode(0)` is `0x00`.

### 5.1 EncryptAndMAC

**TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)**

*Inputs:*
- `key`: A C-byte key. MUST be unique per invocation (see §6.1).
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
&emsp; `tag ← TurboSHAKE128(final_input, 0x61, C)`

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
&emsp; `tag ← TurboSHAKE128(final_input, 0x61, C)`

Return `(plaintext[0] ‖ ... ‖ plaintext[n−1], tag)`.

The caller is responsible for comparing the returned tag against an expected value. TreeWrap does not perform tag verification.

## 6. Security Properties

TreeWrap provides the following security properties under the assumption that the key is unique per invocation and that Keccak-p[1600,12] is indistinguishable from a random permutation. Each property reduces to the Keccak sponge claim via TurboSHAKE128's indifferentiability from a random oracle.

### 6.1 Key Uniqueness

TreeWrap is a deterministic algorithm. Encrypting two different plaintexts with the same key produces ciphertext XOR differences equal to the plaintext XOR differences, fully compromising confidentiality. The key MUST be unique per invocation. When used within a protocol framework, this is typically ensured by deriving the key from transcript state that includes a nonce or counter.

### 6.2 Confidentiality (IND$ for a Single Invocation)

Under a uniformly random key, TreeWrap ciphertext is indistinguishable from a random string of the same length. The argument:

Each leaf cipher, after `init(key, i)`, produces a keystream by squeezing the overwrite duplex. When the key is random, the `init` call is a TurboSHAKE128 evaluation on a random input, and the resulting sponge state is indistinguishable from random (by sponge indifferentiability). The keystream squeezed from this state is therefore pseudorandom.

Since the ciphertext is `plaintext ⊕ keystream` (for each leaf independently), the ciphertext is indistinguishable from random under a random key. Different leaves use different indices, so their keystreams are independent.

The IND$ advantage is bounded by:

$$\varepsilon_{\mathrm{ind\$}} \leq \frac{n \cdot (\sigma + t)^2}{2^{c+1}}$$

where $n$ is the number of leaves, $t$ is the adversary's offline computation, $\sigma$ is the data complexity in Keccak-p blocks, and $c = 256$.

### 6.3 Tag PRF Security

Under a uniformly random key, the TreeWrap tag is a pseudorandom function of the ciphertext. Specifically, for any fixed ciphertext, the tag output of EncryptAndMAC (or DecryptAndMAC) is indistinguishable from a uniformly random $C$-byte string.

The argument:

1. Each leaf's chain value is the output of an overwrite duplex (a sponge evaluation) keyed by the random key and indexed by the leaf position. Under the sponge indifferentiability claim, each chain value is pseudorandom and independent across leaves.

2. The tag is $\mathrm{TurboSHAKE128}(\mathit{final\_input}, \texttt{0x61}, C)$ where $\mathit{final\_input}$ is a deterministic, injective encoding of the chain values. Since the chain values are pseudorandom, $\mathit{final\_input}$ is a pseudorandom input to an independent random oracle (domain byte 0x61 separates the tag computation from leaf ciphers at 0x60 and other uses of TurboSHAKE128).

3. A random oracle on a pseudorandom input produces a pseudorandom output.

The tag PRF advantage is bounded by:

$$\varepsilon_{\mathrm{prf}} \leq \frac{n \cdot (\sigma + t)^2}{2^{c+1}} + \frac{(\sigma + t)^2}{2^{c+1}}$$

The first term covers the leaf chain value pseudorandomness; the second covers the tag accumulation TurboSHAKE128 evaluation.

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

Chain values are accumulated using the KangarooTwelve final node structure: `cv[0]` is absorbed as the "first chunk" of the final node, followed by the 8-byte marker `0x03 0x00...`, then chain values `cv[1]` through `cv[n−1]` as "leaf" contributions, followed by `length_encode(n−1)` and the terminator `0xFF 0xFF`. This is processed by TurboSHAKE128 with domain separation byte 0x61, separating TreeWrap tag computation from both KT128 hashing (0x07) and TreeWrap leaf ciphers (0x60).

The structure is unambiguous: chain values are fixed-size ($C$ bytes each), `length_encode` encodes the number of leaf chain values, and the terminator marks the end. The number of chunks is determined by the ciphertext length, which is assumed to be public.

### 6.10 Side Channels

All leaves process the same key. Implementations MUST ensure constant-time processing regardless of key and plaintext values. The chunk index is not secret and does not require side-channel protection.

### 6.11 Concrete Security Reduction

Each leaf cipher is an overwrite duplex operating on the Keccak-p[1600,12] permutation with capacity $c = 256$ bits. The security argument proceeds in three steps.

**Step 1: Leaf PRF security.** The `init` call is exactly a TurboSHAKE128 evaluation: $\mathrm{TurboSHAKE128}(\mathit{key} \mathbin\| [\mathit{index}]_{\mathrm{64LE}},\, \texttt{0x60})$, since the 40-byte input fits within one sponge block and TreeWrap's padding (domain byte after data, 0x80 at position $R{-}1$) matches TurboSHAKE128's padding format. Subsequent encrypt blocks use a simplified padding (domain byte 0x60 and frame byte 0x80 both at position $R{-}1$, collapsing to 0xE0) that does not correspond to TurboSHAKE128's multi-block structure. However, the leaf's outputs can be expressed as evaluations of the $\mathrm{Keccak}[256]$ sponge function (with Keccak-p[1600,12]) on an injective encoding of the leaf's inputs, following the same overwrite-to-XOR equivalence used by Daemen et al. in Lemma 2 of the overwrite duplex construction. The injectivity holds because: (a) the ciphertext overwrite is injective for a given keystream, (b) block boundaries are determined by the public plaintext length, and (c) the `pad_permute` domain byte position distinguishes blocks of different lengths.

Assuming the Keccak sponge claim holds for Keccak-p[1600,12], the advantage of distinguishing a TreeWrap leaf from an ideal cipher is at most $(\sigma + t)^2 / 2^{c+1}$ where $t$ is the computational complexity and $\sigma$ is the data complexity in blocks. For $c = 256$, this term is negligible for practical workloads.

**Step 2: Tag PRF and collision resistance.** The tag is a TurboSHAKE128 evaluation (domain byte 0x61) over the concatenation of leaf chain values. Since each chain value is pseudorandom under the key (by Step 1), the tag inherits both the PRF security and the collision resistance of TurboSHAKE128. The tag computation adds one additional sponge indifferentiability term.

**Step 3: Combined bound.** Summing all terms for a TreeWrap invocation with $n$ leaves:

$$\varepsilon_{\mathrm{treewrap}} \leq \frac{(n + 1) \cdot (\sigma + t)^2}{2^{c+1}}$$

where the $(n + 1)$ factor accounts for $n$ leaf cipher evaluations plus one tag accumulation evaluation. For typical parameters ($n \leq 2^{32}$ leaves, $\sigma + t \leq 2^{64}$), this is $(2^{32} + 1) \cdot 2^{128} / 2^{257} \approx 2^{-97}$, well within the 128-bit security target for any single invocation. Multi-invocation security is the responsibility of the calling protocol, which must ensure key uniqueness.

## 7. Comparison with Traditional AEAD

TreeWrap differs from traditional AEAD in several respects:

**No internal tag verification.** Traditional AEAD schemes (AES-GCM, ChaCha20-Poly1305, etc.) perform tag comparison inside the Open/Decrypt function and return ⊥ on failure, ensuring plaintext is never released before authentication. TreeWrap's DecryptAndMAC always returns both plaintext and tag, leaving verification to the caller. This is intentional: Thyrse needs the tag for transcript state advancement regardless of verification outcome (see Thyrse specification §10.8).

**Deterministic, no nonce input.** TreeWrap takes only a key and plaintext. It does not accept a nonce or associated data. These are Thyrse's responsibility. The key MUST be unique per invocation.

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
| tag   | `4d74e724544a5498eb490e22778f990b91f4881abadf52aab863144ca037ee2d` |

DecryptAndMAC with the same key and empty ciphertext produces the same tag.

### 9.2 One-Byte Plaintext ($n = 1$)

| Field | Value                                                              |
|-------|--------------------------------------------------------------------|
| len   | 1                                                                  |
| ct    | `f1`                                                               |
| tag   | `11c7e612c89abd32f4f3421557b2e29614eda613b2bcb316a15d02099a867769` |

Flipping bit 0 of the ciphertext (`f0`) yields tag
`9cb439ff6ca083f3656d8fef165dabe0aec3871ef2f8330bfffed17abae1ee53`.

### 9.3 B-Byte Plaintext (exactly one chunk, $n = 1$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8192                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `2550a32191dfa145cadc8364812821be06fd566472804df57be019629b911385` |

Flipping bit 0 of `ct[0]` yields tag
`f242cf24ef7376071cf5f0bf3e960c3c148ed39966ee1ff3542036cc1cf5e4d3`.

### 9.4 B+1-Byte Plaintext (two chunks, minimal second, $n = 2$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 8193                                                               |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `9ed701f2d71ab47bc8e2819e256cb922a46f05497c292c383663fdcf2d6c9877` |

Flipping bit 0 of `ct[0]` yields tag
`658b13c422b23ab28a5e9ea801fba9526803a5e2a465834a83b3ae06a4caabd5`.

### 9.5 4B-Byte Plaintext (four full chunks, $n = 4$)

| Field   | Value                                                              |
|---------|--------------------------------------------------------------------|
| len     | 32768                                                              |
| ct[:32] | `f13513b1112a5cf6cfd4fe007a73351cc808c4837321b9860843b2ef40c06163` |
| tag     | `ae07f24e71e77ee3bc3247bfb87b897cede60b35186a95f00ba089391cf668c0` |

Flipping bit 0 of `ct[0]` yields tag
`4616ecd2b16e75b37a4a56dc2617be6a831483ce0eb9c340d4e05015d8f0ef95`.

Swapping chunks 0 and 1 (bytes 0–8191 and 8192–16383) yields tag
`196883af6fc7d63d123dbcda66c33b4af97b649792288bcbbaa17a23717afae1`.

### 9.6 Round-Trip Consistency

For all vectors above, `DecryptAndMAC(key, ct)` returns the original plaintext and the same tag as `EncryptAndMAC`.
