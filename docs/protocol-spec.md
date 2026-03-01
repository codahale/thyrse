# Thyrse: A Transcript-Based Cryptographic Protocol Framework

**Status:** Draft  
**Version:** 0.3
**Date:** 2026-02-28
**Security Target:** 128-bit

## 1. Introduction

This document specifies Thyrse, a protocol framework that sequences cryptographic operations as frames appended to a transcript. At each finalizing operation, TurboSHAKE128 is evaluated over the transcript to derive keys, chain values, and pseudorandom output. The transcript encoding is recoverable, providing random-oracle-indifferentiable key derivation via the RO-KDF construction of Backendal, Clermont, Fischlin, and Günther. Bulk encryption is delegated to TreeWrap when authenticated or unauthenticated ciphertext is needed.

The framework provides the following operations:

- **Init**: Establish a protocol identity.
- **Mix**: Absorb key material, nonces, or associated data.
- **Mix Stream**: Absorb streaming data too large to fit in memory, via KT128 pre-hashing.
- **Derive**: Produce pseudorandom output that is a function of the full transcript.
- **Ratchet**: Irreversibly advance the protocol state for forward secrecy.
- **Mask / Unmask**: Encrypt or decrypt without authentication. The caller is responsible for authenticating the ciphertext through external mechanisms.
- **Seal / Open**: Encrypt or decrypt with authentication. Open rejects tampered ciphertext and terminates the protocol instance.
- **Fork**: Clone the protocol state into independent branches with distinct identities.

All operations accept a label for domain separation. The full transcript is encoded with a recoverable (left-to-right parseable) encoding, as required by the RO-KDF proof.

## 2. Parameters

| Symbol | Value | Description |
|--------|-------|-------------|
| C | 32 | TreeWrap key and tag size (bytes) |
| H | 64 | Chain value and pre-hash digest size (bytes) |

## 3. Dependencies

**TurboSHAKE128(M, D, ℓ):** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D` (0x01–0x7F), and an output length `ℓ` in bytes.

**KT128(M, S, ℓ):** KangarooTwelve as specified in RFC 9861. Takes a message `M`, a customization string `S`, and an output length `ℓ` in bytes.

**TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag):** As specified in the TreeWrap specification. Takes a C-byte key and arbitrary-length plaintext; returns same-length ciphertext and a C-byte tag.

**TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag):** Takes a C-byte key and arbitrary-length ciphertext; returns same-length plaintext and a C-byte tag. TreeWrap does not perform tag verification; the caller is responsible for comparing the returned tag against an expected value.

## 4. Integer Encoding

All integer encodings use `left_encode` as defined in NIST SP 800-185, consistent with KangarooTwelve. `left_encode(x)` encodes a non-negative integer `x` as a byte string consisting of the length of the encoding (in bytes) followed by the big-endian encoding of `x`. For example:

- `left_encode(0)` = `0x01 0x00`
- `left_encode(127)` = `0x01 0x7F`
- `left_encode(256)` = `0x02 0x01 0x00`

## 5. Encoding Convention

For a byte string `x`, we define:

**`length_encode(x)`** = `left_encode(len(x)) ‖ x`

This encoding is self-delimiting when parsed left-to-right: the `left_encode` prefix determines the length of `x`, and the subsequent `len(x)` bytes are `x` itself. A concatenation of `length_encode` values is therefore recoverable — a parser can unambiguously extract each element.

## 6. Domain Separation Bytes

Each TurboSHAKE128 evaluation uses a domain separation byte that identifies the purpose of the output:

| Byte | Purpose                        | Used by             |
|------|--------------------------------|---------------------|
| 0x07 | Standard TurboSHAKE128 / KT128 | KT128 pre-hashing   |
| 0x20 | Chain value derivation         | Derive, Mask, Seal  |
| 0x21 | Derive output                  | Derive              |
| 0x22 | Mask key derivation            | Mask / Unmask       |
| 0x23 | Seal key derivation            | Seal / Open         |
| 0x24 | Ratchet chain derivation       | Ratchet             |
| 0x60 | TreeWrap intermediate block    | TreeWrap (internal) |
| 0x61 | TreeWrap final block           | TreeWrap (internal) |
| 0x62 | TreeWrap tag accumulation      | TreeWrap (internal) |

All domain bytes are in the range 0x01–0x7F as required by TurboSHAKE128.

## 7. Operation Codes

| Code | Operation | Finalizing |
|------|-----------|------------|
| 0x10 | INIT | No |
| 0x11 | MIX | No |
| 0x12 | MIX_STREAM | No |
| 0x13 | FORK | No |
| 0x14 | DERIVE | Yes |
| 0x15 | RATCHET | Yes |
| 0x16 | MASK | Yes |
| 0x17 | SEAL | Yes |
| 0x18 | CHAIN | No |

## 8. Protocol State

The protocol state is a byte string called the **transcript**, initially empty. Operations append frames to the transcript. Finalizing operations evaluate TurboSHAKE128 over the transcript and then reset it.

## 9. Security Requirements

### 9.1 Probabilistic Transcript

The confidentiality of Mask (IND-CPA) and Seal (IND-CCA2) depends on the TreeWrap key being indistinguishable from random, which in turn requires the transcript at the point of finalization to contain at least one unpredictable input. Callers MUST ensure that a fresh, unpredictable value (such as a nonce or ephemeral key) has been absorbed via Mix before any Mask or Seal operation.

If two protocol runs reach the same transcript state and then Mask or Seal different plaintexts, they derive the same TreeWrap key. This is catastrophic: TreeWrap with a repeated key leaks plaintext XOR differences, fully compromising confidentiality.

This requirement is analogous to the nonce requirement of conventional AEAD schemes. It is the caller's responsibility and is not enforced by the framework.

### 9.2 Derive Output Uniqueness

Similarly, Derive output is pseudorandom only if the transcript is unpredictable at the point of finalization. For use cases where Derive serves as a random oracle (e.g., VOPRFs), the transcript MUST contain an unpredictable input. For deterministic key derivation from known inputs, the output is a deterministic function of the transcript and is not pseudorandom — it is a PRF output, which may still be sufficient depending on the application's security requirements.

## 10. Operations

### 10.1 Init

Establishes the protocol identity. The Init label provides protocol-level domain separation: two protocols using different Init labels produce cryptographically independent transcripts even if all subsequent operations are identical. See §11 for transcript validity requirements.

**Init(label)**

&emsp; `transcript ← 0x10 ‖ length_encode(label)`

### 10.2 Mix

Absorbs data into the protocol transcript. Used for key material, nonces, associated data, and any protocol input that fits in memory.

**Mix(label, data)**

&emsp; `transcript ← transcript ‖ 0x11 ‖ length_encode(label) ‖ length_encode(data)`

### 10.3 Mix Stream

Absorbs streaming data that may not fit in memory. The data is pre-hashed through KT128 to produce a fixed-size commitment. The Init label is used as the KT128 customization string, binding the digest to the protocol identity.

**MixStream(label, data)**

&emsp; `digest ← KT128(data, init_label, H)`  
&emsp; `transcript ← transcript ‖ 0x12 ‖ length_encode(label) ‖ length_encode(digest)`

Here `init_label` is the label passed to the Init operation that established this protocol instance. Implementations MUST retain this value for the lifetime of the instance.

### 10.4 Fork

Clones the protocol state into N independent branches and modifies the base. Each branch receives a left-encoded ordinal ID for domain separation. The base receives ordinal 0; clones receive ordinals 1 through N.

**Fork(label, values...) → clones[]**

Let `N = len(values)` and let `t` be the current value of `transcript`.

For the base (ordinal 0):

&emsp; `transcript ← t ‖ 0x13 ‖ length_encode(label) ‖ left_encode(N) ‖ left_encode(0) ‖ length_encode("")`

For each clone `i` (1 ≤ i ≤ N), create an independent protocol state with:

&emsp; `transcript ← t ‖ 0x13 ‖ length_encode(label) ‖ left_encode(N) ‖ left_encode(i) ‖ length_encode(values[i-1])`

Fork does not finalize. All N+1 branches share the same transcript up to `t` and diverge via their ordinals and values.

Example: `Fork("role", "prover", "verifier")` produces three protocol states. The base continues with ordinal 0 and an empty value. Clone 1 gets ordinal 1 with value "prover". Clone 2 gets ordinal 2 with value "verifier".

### 10.5 Derive

Produces pseudorandom output that is a deterministic function of the full transcript. Finalizes the current transcript and begins a new one.

**Derive(label, output_len) → output**

Precondition: `output_len` MUST be greater than zero. Use Ratchet for zero-output-length state advancement.

1. Append the frame:

&emsp; `transcript ← transcript ‖ 0x14 ‖ length_encode(label) ‖ left_encode(output_len)`

2. Evaluate TurboSHAKE128 twice over the same transcript with different domain bytes:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x20, H)`  
&emsp; `output ← TurboSHAKE128(transcript, 0x21, output_len)`

3. Reset the transcript:

&emsp; `transcript ← 0x18 ‖ 0x14 ‖ left_encode(1) ‖ length_encode(chain_value)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `output`.

### 10.6 Ratchet

Irreversibly advances the protocol state. No user-visible output is produced.

**Ratchet(label)**

1. Append the frame:

&emsp; `transcript ← transcript ‖ 0x15 ‖ length_encode(label)`

2. Derive a chain value:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x24, H)`

3. Reset the transcript:

&emsp; `transcript ← 0x18 ‖ 0x15 ‖ left_encode(1) ‖ length_encode(chain_value)`

### 10.7 Mask / Unmask

Encrypts (Mask) or decrypts (Unmask) without authentication. Use Mask when integrity is provided by an external mechanism (e.g., a signature over the transcript) or when confidentiality alone is sufficient.

**Mask(label, plaintext) → ciphertext**

1. Append the frame:

&emsp; `transcript ← transcript ‖ 0x16 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x20, H)`  
&emsp; `key ← TurboSHAKE128(transcript, 0x22, C)`

3. Encrypt:

&emsp; `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`

4. Reset the transcript:

&emsp; `transcript ← 0x18 ‖ 0x16 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `ciphertext`. The tag is not transmitted.

**Unmask(label, ciphertext) → plaintext**

1. Append the frame (identical to Mask):

&emsp; `transcript ← transcript ‖ 0x16 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x20, H)`  
&emsp; `key ← TurboSHAKE128(transcript, 0x22, C)`

3. Decrypt:

&emsp; `(plaintext, tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript:

&emsp; `transcript ← 0x18 ‖ 0x16 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

Return `plaintext`.

*Warning:* Any application-level processing of the unmasked plaintext MUST be treated as untrusted and safely buffered until an external authenticating operation (such as verifying a signature over a subsequent Derive output) has succeeded.

### 10.8 Seal / Open

Encrypts (Seal) or decrypts (Open) with authentication. Use Seal when the ciphertext must be verified on receipt. A failed Open indicates tampering and permanently invalidates the protocol instance.

**Seal(label, plaintext) → ciphertext ‖ tag**

1. Append the frame:

&emsp; `transcript ← transcript ‖ 0x17 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x20, H)`  
&emsp; `key ← TurboSHAKE128(transcript, 0x23, C)`

3. Encrypt:

&emsp; `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`  

4. Reset the transcript:

&emsp; `transcript ← 0x18 ‖ 0x17 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `ciphertext ‖ tag`.

**Open(label, ciphertext, tag) → plaintext or ⊥**

1. Append the frame (identical to Seal):

&emsp; `transcript ← transcript ‖ 0x17 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

&emsp; `chain_value ← TurboSHAKE128(transcript, 0x20, H)`  
&emsp; `key ← TurboSHAKE128(transcript, 0x23, C)`

3. Decrypt:

&emsp; `(plaintext, computed_tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript (unconditionally):

&emsp; `transcript ← 0x18 ‖ 0x17 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(computed_tag)`

5. Verify:

&emsp; If `computed_tag ≠ tag` (constant-time comparison), discard `plaintext` and return ⊥. The protocol instance is permanently desynchronized and MUST be discarded immediately.

Return `plaintext`.

### 10.9 Utility Operations

**Clone() → copy**

Returns an independent copy of the protocol state (transcript and, in sponge-based implementations, the full sponge state and Init label). The original and clone evolve independently. Clone does not append a frame to the transcript.

*Warning:* Because Clone does not append a frame, applying identical operations to the original and the clone will produce identical transcripts, potentially leading to catastrophic key reuse in Mask or Seal. Callers SHOULD use Fork to create independent protocol branches unless they are explicitly managing transcript divergence (e.g., repeating an operation for benchmarking, or transferring state from sender to receiver).

**Clear()**

Overwrites the protocol state with zeros and invalidates the instance. Implementations MUST zero the sponge state, any buffered key material, and the stored Init label. After Clear, the instance MUST NOT be used.

## 11. Recoverability

The encoding of every operation frame is recoverable by left-to-right parsing. Given a transcript byte string, a parser can unambiguously extract each operation:

1. Read one byte: the operation code.
2. Based on the operation code:
   - **INIT (0x10):** Parse `length_encode(label)`.
   - **MIX (0x11):** Parse `length_encode(label)`, then `length_encode(data)`.
   - **MIX_STREAM (0x12):** Parse `length_encode(label)`, then `length_encode(digest)`.
   - **FORK (0x13):** Parse `length_encode(label)`, then `left_encode(N)`, then `left_encode(ordinal)`, then `length_encode(value)`.
   - **DERIVE (0x14):** Parse `length_encode(label)`, then `left_encode(output_len)`.
   - **RATCHET (0x15):** Parse `length_encode(label)`.
   - **MASK (0x16):** Parse `length_encode(label)`.
   - **SEAL (0x17):** Parse `length_encode(label)`.
   - **CHAIN (0x18):** Read one byte: the origin operation code (0x14, 0x15, 0x16, or 0x17). Parse `left_encode(n)`, then parse `n` instances of `length_encode(value)`.
3. The next byte is the operation code of the subsequent operation, or the transcript ends.

Since `left_encode` is self-delimiting and all variable-length fields are length-prefixed, the encoding is injective and recoverable. This satisfies the requirement of the RO-KDF construction.

**Transcript validity.** A valid transcript MUST begin with either an INIT frame (0x10) for the first instance or a CHAIN frame (0x18) for subsequent instances after finalization. Implementations MUST reject any operation on an empty transcript other than Init. A CHAIN origin byte MUST be one of 0x14, 0x15, 0x16, 0x17. Any other leading byte or origin byte indicates a malformed transcript.

## 12. Implementation Notes

### 12.1 Sponge State Reuse

Although the transcript is described as a byte string that is hashed in its entirety at each finalization, an implementation SHOULD maintain a running TurboSHAKE128 sponge state. Non-finalizing operations (Init, Mix, Mix Stream, Fork) absorb their frames incrementally into the sponge without forcing permutation boundaries. Finalizing operations clone the sponge state and finalize the clones with their respective domain bytes. This avoids re-hashing the full transcript on each finalization.

The two TurboSHAKE128 evaluations at each finalization (chain value + output/key) require one clone and two independent finalizations, which may execute in parallel on platforms with SIMD support for Keccak-p[1600,12].

### 12.2 Incremental Absorption

Multiple small Mix operations pack contiguously into the sponge rate (168 bytes for TurboSHAKE128) with no forced permutation boundaries. The sponge permutation occurs only when the rate buffer fills naturally. For a typical AEAD header — Init + Mix(key) + Mix(nonce) + Mix(ad) with a 32-byte key, 12-byte nonce, and 16-byte AD — the total frame size is approximately 80 bytes, fitting within a single rate block with zero permutation calls before encryption begins.

### 12.3 Constant-Time Operation

Implementations MUST ensure constant-time processing for all secret data. Tag verification in Open MUST use constant-time comparison. TreeWrap key derivation and encryption MUST not branch on secret values.

### 12.4 Memory Sanitization

**Plaintext on failed Open.** Open decrypts ciphertext before verifying the tag. If verification fails, the plaintext buffer contains unauthenticated data that MUST be zeroed before returning. Implementations that decrypt in-place MUST overwrite the buffer with zeros (not with the original ciphertext, which may itself be attacker-controlled). Callers MUST NOT read or act on plaintext from a failed Open.

**Protocol state.** The Clear operation (§10.9) zeros the sponge state, buffered key material, and stored Init label. Implementations SHOULD also zero derived TreeWrap keys and intermediate chain values as soon as they are no longer needed. For forward secrecy to hold after Ratchet, the pre-Ratchet sponge state MUST be erased; retaining it in memory defeats the purpose of ratcheting.

**Language-level considerations.** In languages with garbage collection or compiler optimizations that may elide stores to dead memory, implementations MUST use platform-specific secure-zeroing primitives (e.g., `explicit_bzero`, `SecureZeroMemory`, `volatile` writes) to ensure that sensitive data is actually erased.

## 13. Security Considerations

### 13.1 Security Model

The security argument proceeds in two parts: per-instance security via the RO-KDF construction, and sequential composition across chain boundaries.

**Per-instance security.** Each transcript instance — from its initial CHAIN frame (or INIT, for Instance 0) through finalization — is a single TurboSHAKE128 evaluation on a recoverably-encoded input. This matches the RO-KDF construction of Backendal, Clermont, Fischlin, and Günther (Figure 4, Theorems 8 and 9 of ePrint 2025/657). Under TurboSHAKE128's indifferentiability from a random oracle, the RO-KDF proof gives: the output of each finalization is indistinguishable from random as long as at least one input to the transcript instance is unpredictable. In the notation of Backendal et al., the recoverable encoding $\langle\cdot\rangle$ is the frame encoding defined in §§4–5 of this spec, and the source collection corresponds to the key material, nonces, and chain values absorbed into the instance.

Two finalizations of the same transcript with different domain bytes (e.g., chain value with 0x20 and derived output with 0x21) produce independent outputs. This follows from modeling TurboSHAKE128 with distinct domain bytes as independent random oracles, which is justified by TurboSHAKE128's domain separation mechanism: the domain byte is absorbed into the sponge state at a position that is unambiguously separated from the message, making $\mathrm{TurboSHAKE128}(M, D_1, \ell)$ and $\mathrm{TurboSHAKE128}(M, D_2, \ell)$ independent functions when $D_1 \neq D_2$.

**Sequential composition across chain boundaries.** The RO-KDF proof covers a single hash evaluation, not a chain of evaluations where one output feeds into the next instance's input. The composition argument is as follows.

Consider Instance $k$, which finalizes with domain bytes 0x20 (chain) and some output domain byte $D$ (derive/key). Let $\mathit{cv}_k$ denote the chain value and $\mathit{out}_k$ denote the derived output or key. Since these come from independent random oracles on the same transcript, $\mathit{cv}_k$ and $\mathit{out}_k$ are independent. In particular, an adversary who observes $\mathit{out}_k$ (or ciphertext encrypted under a key derived from $\mathit{out}_k$) gains no information about $\mathit{cv}_k$.

Instance $k{+}1$ begins by absorbing the CHAIN frame containing $\mathit{cv}_k$. If Instance $k{+}1$ also absorbs additional key material or other unpredictable data via Mix operations, the RO-KDF proof applies directly to Instance $k{+}1$ with multiple unpredictable inputs.

If Instance $k{+}1$ absorbs no new key material — only the CHAIN frame and protocol metadata — then $\mathit{cv}_k$ is the sole source of unpredictability. In the random oracle model, $\mathit{cv}_k$ is uniformly random (it is the output of an RO on a transcript that the adversary has not queried, because doing so would require predicting the unpredictable inputs to Instance $k$). Therefore $\mathit{cv}_k$ satisfies the unpredictability requirement of Theorem 8 in Backendal et al., and the RO-KDF proof applies to Instance $k{+}1$.

By induction, this argument extends to any number of chain boundaries. The security of Instance $k{+}1$ reduces to the security of Instance $k$ (via the pseudorandomness of $\mathit{cv}_k$), which ultimately reduces to the unpredictability of the original key material in Instance 0.

**Computational bound.** In the computational model, each chain boundary incurs TurboSHAKE128's indifferentiability advantage. For a protocol with $q$ finalizations and an adversary making $t$ offline queries, the total advantage is bounded by $q$ times the per-instance RO-KDF bound plus $q$ times the TurboSHAKE128 indifferentiability term. The concrete bound is given in §13.8.

### 13.2 Chain Value Properties

Each chain value is $H = 64$ bytes (512 bits). The birthday bound for chain value collisions across instances is $2^{256}$, far exceeding the 128-bit security target.

Forward secrecy is achieved by Ratchet: after Ratchet, the transcript is reset to contain only the chain value. An adversary who compromises the post-Ratchet state learns the chain value but cannot invert TurboSHAKE128 to recover the prior transcript, and therefore cannot recover keys or outputs derived from earlier instances. Note that forward secrecy requires the prior transcript's sponge state to be erased from memory; this is an implementation obligation (see §12.4).

### 13.3 Pre-Hash Collision Resistance

Mix Stream absorbs a KT128 digest rather than the raw data. The $H = 64$ byte digest provides 256-bit collision resistance under the Keccak sponge claim, exceeding the 128-bit security target. The Init label is used as the KT128 customization string, ensuring that MixStream digests are protocol-specific: two different protocols produce different digests for the same data.

### 13.4 Mask / Unmask Security

Mask provides confidentiality but not authentication. The security argument relies on two properties of TreeWrap:

**IND-CPA from key pseudorandomness.** The TreeWrap key is derived from TurboSHAKE128 with domain byte 0x22 on the current transcript. Under the per-instance RO-KDF argument (§13.1), this key is indistinguishable from random as long as the transcript contains at least one unpredictable input. TreeWrap's confidentiality under a random key follows from the leaf cipher's PRF security under the Keccak sponge claim (see TreeWrap specification §6.2). Therefore, Mask provides IND-CPA confidentiality.

**Tag as PRF output.** The full TreeWrap tag absorbed into the CHAIN frame is a deterministic function of the TreeWrap key and the ciphertext. For the composition argument in §13.1 to hold, the tag must not leak information about the chain value $\mathit{cv}_k$. Since the tag is derived from a TreeWrap key that is independent of $\mathit{cv}_k$ (different domain bytes on the same transcript), and the tag is a PRF of the key applied to the ciphertext (see TreeWrap specification §6.3), the tag is pseudorandom and independent of $\mathit{cv}_k$. Therefore, absorbing the tag into the next instance's CHAIN frame does not compromise the chain value's unpredictability.

If the ciphertext is tampered with, the sender and receiver compute different tags. Their transcripts diverge, and all subsequent operations produce different results. However, Mask alone does not provide integrity guarantees. Applications requiring integrity should use Seal or authenticate the ciphertext externally.

### 13.5 Seal / Open Security

Seal provides confidentiality and $8C = 256$ bits of authentication. The confidentiality and composition arguments are identical to Mask (§13.4), with domain byte 0x23 for key derivation instead of 0x22.

**Authentication.** The tag appended to the ciphertext is the full $C$-byte TreeWrap tag. Under a random key, the tag is a PRF of the ciphertext (TreeWrap specification §6.3). An adversary making $S$ forgery attempts therefore succeeds with probability at most:

$$\varepsilon_{\mathrm{forge}} \leq \frac{S}{2^{8C}} + \varepsilon_{\mathrm{prf}}$$

where $\varepsilon_{\mathrm{prf}}$ is the TreeWrap tag PRF advantage (bounded by $(n{+}1) \cdot (\sigma{+}t)^2 / 2^{257}$ per TreeWrap specification §6.11). For $C = 32$ bytes, the forgery bound is $S / 2^{256}$ plus a negligible term.

**Committing security.** The full $C$-byte tag absorbed into the CHAIN frame provides CMT-4 committing security via TreeWrap's construction: the tag is a collision-resistant function of (key, ciphertext), and since TreeWrap encryption is invertible per-key, this commits to (key, plaintext). See the TreeWrap specification §6.5 for the detailed argument.

**Failed Open.** Open advances the transcript unconditionally. On verification failure, the receiver's transcript diverges from the sender's (different `full_tag` values in the CHAIN frame), permanently desynchronizing the protocol state. After a failed Open, the protocol instance MUST be discarded.

### 13.6 Fork Security

Fork does not finalize. All $N{+}1$ branches share identical transcript up to the fork point and diverge via their ordinals and (for clones) branch-specific values. The ordinal alone ensures the base is distinct from all clones. Callers MUST ensure clone values are distinct from each other.

### 13.7 Domain Byte and Operation Code Separation

All operation codes are in the range 0x10–0x18. All TurboSHAKE128 domain bytes used by this framework are in the range 0x20–0x24 (protocol operations) and 0x60–0x61 (TreeWrap). KT128 uses domain byte 0x07. These ranges are disjoint, eliminating any possibility of confusion between operation codes and domain bytes.

This provides a robust defense-in-depth layer against cross-operation state confusion. For example, in Mask and Seal, the operation codes (0x16 vs 0x17) force the transcripts to diverge *before* finalization, and the sponge finalizations use distinct domain bytes (0x22 vs 0x23) to derive the keys, providing redundant cryptographic separation.

### 13.8 Concrete Security Reduction

This section gives the full reduction from protocol security to the Keccak sponge claim. The reduction proceeds in four steps: replace Keccak-p with an ideal permutation, replace the sponge with independent random oracles, apply the RO-KDF argument per instance with inductive composition, and reduce TreeWrap security under derived keys.

**Parameters.**

| Symbol | Meaning |
|--------|---------|
| $q$ | Total number of finalizing operations across the protocol lifetime |
| $\sigma$ | Total data complexity: number of Keccak-p[1600,12] calls made by the protocol |
| $t$ | Adversary's offline computation budget in Keccak-p[1600,12] calls |
| $S$ | Number of forgery attempts against Seal/Open |
| $c$ | TurboSHAKE128 capacity = 256 bits |
| $H$ | Chain value length = 512 bits |

**Step 1: Ideal permutation assumption.** The Keccak sponge claim asserts that Keccak-p[1600,12] is indistinguishable from a uniformly random permutation on $\{0,1\}^{1600}$. This is a computational assumption analogous to the assumption that AES is a pseudorandom permutation. All subsequent terms are conditional on this assumption. If an adversary distinguishes Keccak-p[1600,12] from a random permutation with advantage $\varepsilon_{\mathrm{perm}}$, this term propagates additively into the final bound.

**Step 2: Sponge indifferentiability.** Under the ideal permutation model, the sponge construction with capacity $c$ is indifferentiable from a random oracle (Bertoni, Daemen, Peeters, Van Assche, 2008). The indifferentiability advantage is bounded by:

$$\varepsilon_{\mathrm{indiff}} \leq \frac{(\sigma + t)^2}{2^{c+1}} = \frac{(\sigma + t)^2}{2^{257}}$$

This replacement covers all TurboSHAKE128 evaluations in the protocol: backbone finalizations (domain bytes 0x20–0x24), TreeWrap leaf ciphers (0x60), TreeWrap tag accumulation (0x61), and KT128 pre-hashing (0x07, which uses TurboSHAKE128 internally). After this step, each (message, domain_byte) pair maps to an independent uniformly random output.

TurboSHAKE128 evaluations with distinct domain bytes are modeled as independent random oracles. This follows from the domain byte being absorbed at a structurally distinct position (the pad byte in the sponge finalization), which makes $\mathrm{TurboSHAKE128}(M, D_1, \ell)$ and $\mathrm{TurboSHAKE128}(M, D_2, \ell)$ evaluations of independent sponge instances for $D_1 \neq D_2$. No additional advantage term is incurred.

**Step 3: RO-KDF per instance and composition.** In the random oracle model, each transcript instance is a single evaluation of an RO on a recoverably-encoded input. By Theorem 8 of Backendal et al. (ePrint 2025/657), the output of each instance is indistinguishable from random as long as at least one input source is unpredictable:

$$\varepsilon_{\mathrm{kdf}}(k) \leq 2 \cdot \mathrm{Adv}^{\mathrm{up}}_{\Sigma}(k)$$

where $\mathrm{Adv}^{\mathrm{up}}_{\Sigma}(k)$ is the unpredictability advantage of the source collection for Instance $k$.

For Instance 0, the source collection is the key material and nonces absorbed via Mix. $\mathrm{Adv}^{\mathrm{up}}_{\Sigma}(0)$ is determined by the caller's key generation and nonce selection.

For Instance $k > 0$, the chain value $\mathit{cv}_{k-1}$ serves as an unpredictable source. In the random oracle model, $\mathit{cv}_{k-1} = \mathrm{RO}_{0\mathrm{x}20}(\mathit{transcript}_{k-1})$ is uniformly random and independent of the output derived from $\mathit{transcript}_{k-1}$ (which uses a different domain byte). An adversary who has observed all derived outputs and ciphertexts from Instances 0 through $k{-}1$ has no information about $\mathit{cv}_{k-1}$, because:

- $\mathit{cv}_{k-1}$ is the output of $\mathrm{RO}_{0\mathrm{x}20}$, independent of outputs from $\mathrm{RO}_{0\mathrm{x}21}$, $\mathrm{RO}_{0\mathrm{x}22}$, $\mathrm{RO}_{0\mathrm{x}23}$.
- To query $\mathrm{RO}_{0\mathrm{x}20}$ on $\mathit{transcript}_{k-1}$, the adversary would need to construct the full transcript, which requires predicting the unpredictable inputs to Instance $k{-}1$.

For Mask and Seal instances, the CHAIN frame also absorbs the TreeWrap tag. The tag is a deterministic function of the TreeWrap key (from $\mathrm{RO}_{0\mathrm{x}22}$ or $\mathrm{RO}_{0\mathrm{x}23}$) and the ciphertext. Since the key is independent of $\mathit{cv}_{k-1}$ (different domain byte) and the tag is a PRF of the key (see Step 4), the tag reveals no information about $\mathit{cv}_{k-1}$. The adversary who observes both the ciphertext and the derived key's effects still cannot predict $\mathit{cv}_{k-1}$.

Therefore, $\mathit{cv}_{k-1}$ is unpredictable as a source for Instance $k$, and the RO-KDF bound applies:

$$\varepsilon_{\mathrm{kdf}}(k) \leq 2 \cdot \mathrm{Adv}^{\mathrm{up}}_{\mathit{cv}}$$

where $\mathrm{Adv}^{\mathrm{up}}_{\mathit{cv}} \leq \varepsilon_{\mathrm{kdf}}(k{-}1)$ by induction.

Unrolling the induction across $q$ instances and accounting for chain value collisions:

$$\varepsilon_{\mathrm{compose}} \leq q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{q^2}{2^{8H+1}}$$

The second term bounds the probability of a chain value collision across any two instances (birthday bound on $H = 64$ bytes = 512 bits), which would cause two instances to produce identical transcripts and violate the freshness requirement. This gives $q^2 / 2^{513}$.

**Step 4: TreeWrap under derived keys.** After Steps 2–3, each TreeWrap key is indistinguishable from a uniform random $C$-byte string. TreeWrap's security under a random key reduces to the sponge claim via:

- **Confidentiality (IND-CPA):** Each TreeWrap leaf cipher is a TurboSHAKE128 evaluation with domain byte 0x60, which is a PRF under the sponge indifferentiability established in Step 2. The IND-CPA advantage is absorbed into $\varepsilon_{\mathrm{indiff}}$ via the data complexity $\sigma$.

- **Tag PRF security:** The TreeWrap tag accumulation uses TurboSHAKE128 with domain byte 0x61. Under the random oracle model, the tag is a pseudorandom function of the key and ciphertext. The PRF advantage is absorbed into $\varepsilon_{\mathrm{indiff}}$.

- **Forgery resistance:** An adversary making $S$ forgery attempts against Seal/Open succeeds with probability at most:

$$\varepsilon_{\mathrm{forge}} \leq \frac{S}{2^{8T}} = \frac{S}{2^{128}}$$

- **Committing security (CMT-4):** Finding $(K_1, P_1) \neq (K_2, P_2)$ that produce the same full tag requires a collision in the tag accumulation function, bounded by the sponge collision resistance term already captured in $\varepsilon_{\mathrm{indiff}}$.

See the TreeWrap specification for the detailed per-primitive bounds.

**Combined bound.** Summing all terms:

$$\varepsilon_{\mathrm{total}} \leq \varepsilon_{\mathrm{perm}} + \frac{(\sigma + t)^2}{2^{257}} + q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{q^2}{2^{513}} + \frac{S}{2^{128}}$$

where:
- $\varepsilon_{\mathrm{perm}}$ is the advantage of distinguishing Keccak-p[1600,12] from a random permutation (conjectured negligible).
- $(\sigma + t)^2 / 2^{257}$ is the sponge indifferentiability term, covering all TurboSHAKE128 evaluations globally (backbone, TreeWrap leaves, TreeWrap tags, KT128 pre-hashing).
- $q \cdot \varepsilon_{\mathrm{kdf}}(0)$ is $q$ times the per-instance RO-KDF bound, which depends on the unpredictability of the caller's key material.
- $q^2 / 2^{513}$ bounds chain value collisions.
- $S / 2^{128}$ bounds Seal forgery.

For typical parameters — $q \leq 2^{48}$ finalizations, $\sigma + t \leq 2^{64}$ total permutation queries (representing exabytes of data and computation), and $S \leq 2^{48}$ forgery attempts — the individual terms evaluate to:

- Indifferentiability: $(2^{64})^2 / 2^{257} = 2^{-129}$
- Chain collisions: $(2^{48})^2 / 2^{513} = 2^{-417}$
- Forgery: $2^{48} / 2^{128} = 2^{-80}$

The indifferentiability and forgery terms dominate. The 128-bit security target is met as long as the caller ensures $\varepsilon_{\mathrm{kdf}}(0) \leq 2^{-128}$ (i.e., the original key material has at least 128 bits of unpredictability) and the total data complexity satisfies $\sigma + t \leq 2^{64}$.

### 13.9 Multi-User Security

The bound in §13.8 covers a single protocol session. In a multi-user setting with $U$ independent sessions (each with an independent key), the adversary's advantage increases because it can target any session.

**Multi-user sponge bound.** The sponge indifferentiability term becomes a global resource shared across all sessions. If the adversary makes $t$ offline Keccak-p queries and the $U$ sessions collectively process $\sigma_{\mathrm{total}}$ sponge blocks, the indifferentiability term is:

$$\varepsilon_{\mathrm{indiff}} \leq \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}}$$

This is unchanged in form — $\sigma_{\mathrm{total}}$ simply sums the data complexity across all sessions. The adversary does not gain a per-user multiplier on the indifferentiability term because the sponge claim is a global property of the permutation.

**Multi-user key recovery.** The adversary can attempt to recover any of the $U$ session keys. Under the RO-KDF argument, each session key is derived from a TurboSHAKE128 evaluation on a transcript containing unpredictable key material. The adversary can query the random oracle on candidate inputs and check whether any of the $U$ sessions matches. This gives a multi-target advantage of:

$$\varepsilon_{\mathrm{mu\text{-}key}} \leq U \cdot \varepsilon_{\mathrm{kdf}}(0)$$

For 128-bit keys, $\varepsilon_{\mathrm{kdf}}(0) \approx t / 2^{128}$, so $\varepsilon_{\mathrm{mu\text{-}key}} \approx U \cdot t / 2^{128}$. To maintain 128-bit security against an adversary with budget $t = 2^{64}$ across $U = 2^{32}$ users, the per-key unpredictability must be at least $128 + 32 = 160$ bits — which is satisfied by the 256-bit key material typical of Diffie-Hellman or KEM-based key exchange.

**Multi-user forgery.** The adversary can attempt forgeries against any of the $U$ sessions. If each session processes at most $q$ Seal operations, the total forgery advantage is:

$$\varepsilon_{\mathrm{mu\text{-}forge}} \leq \frac{S}{2^{128}}$$

where $S$ is the total number of forgery attempts across all sessions.

**Multi-user chain collisions.** If two sessions happen to reach the same chain value at any point, their subsequent outputs are correlated. The probability of a cross-session chain collision is:

$$\varepsilon_{\mathrm{mu\text{-}chain}} \leq \frac{(U \cdot q)^2}{2^{513}}$$

where $q$ is the maximum number of finalizations per session. For $U = 2^{32}$ sessions with $q = 2^{32}$ finalizations each, this is $(2^{64})^2 / 2^{513} = 2^{-385}$.

**Combined multi-user bound:**

$$\varepsilon_{\mathrm{mu\text{-}total}} \leq \varepsilon_{\mathrm{perm}} + \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}} + U \cdot q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{(U \cdot q)^2}{2^{513}} + \frac{S}{2^{128}}$$

**Ratcheting as mitigation.** The multi-user key recovery term $U \cdot \varepsilon_{\mathrm{kdf}}(0)$ reflects the adversary's ability to correlate offline computation with any of $U$ sessions over the session's entire lifetime. Ratcheting limits this exposure. After a Ratchet operation, the session state contains only a chain value — a 512-bit pseudorandom string with no algebraic structure that could be exploited in a multi-target search. An adversary who targets the pre-Ratchet key material must do so before the Ratchet occurs (or within the window of operations between Ratchets).

If a session Ratchets every $W$ finalizing operations, the effective multi-target window is reduced: the adversary must target a specific epoch of $W$ operations rather than the full session lifetime. The key recovery term becomes:

$$\varepsilon_{\mathrm{mu\text{-}key\text{-}ratcheted}} \approx \frac{U \cdot t}{2^{128}}$$

per epoch, but the adversary must choose which epoch to target. With $q/W$ epochs per session, the adversary's best strategy is to target the epoch with the weakest key material, which is typically the initial key establishment. Ratcheting does not improve the initial key recovery bound, but it ensures that compromising any single epoch does not compromise the full session — this is the forward secrecy property (§13.2).

For long-lived sessions (messaging protocols, persistent tunnels), periodic Ratcheting every few hundred operations is strongly recommended.

### 13.10 Practical Data Limits

The theoretical bounds in §§13.8–13.9 are expressed in terms of sponge blocks (168-byte rate for TurboSHAKE128). This section converts them to practical data volumes.

**Sponge blocks per operation.** Each Keccak-p[1600,12] invocation processes one sponge block of $R = 168$ bytes. The data complexity $\sigma$ counts the total number of Keccak-p invocations across all protocol and TreeWrap operations:

- A Mix operation absorbing $d$ bytes of data costs $\lceil(\text{frame overhead} + d) / 168\rceil$ blocks, but since non-finalizing operations pack into the running sponge state, the cost is amortized. A typical AEAD header (Init + Mix(key) + Mix(nonce) + Mix(ad)) costs 0 permutation calls if the total frame size fits in one rate block ($\leq 168$ bytes).

- A finalizing operation (Derive, Ratchet, Mask, Seal) forces at least 2 Keccak-p calls (one per TurboSHAKE128 evaluation for the two domain-byte clones), plus however many calls are needed to squeeze the output.

- TreeWrap encryption of $m$ bytes costs $\lceil m / 167 \rceil$ Keccak-p calls per leaf (167 data bytes per block, with position 167 reserved for the duplex pad), plus one call per leaf for `init`, plus one call per leaf for `chain_value`, plus the tag accumulation TurboSHAKE128. For a single leaf processing $B = 8192$ bytes: $\lceil 8192/167 \rceil + 2 = 51$ calls, plus a share of the tag computation.

**Data volume limits.** The indifferentiability term $(\sigma + t)^2 / 2^{257}$ must remain negligible. Setting a target of $\varepsilon_{\mathrm{indiff}} \leq 2^{-128}$ gives:

$$(\sigma + t)^2 \leq 2^{129} \quad\Longrightarrow\quad \sigma + t \leq 2^{64.5}$$

This is the total budget shared between the protocol's data processing ($\sigma$) and the adversary's offline computation ($t$). Assuming a generous offline budget of $t = 2^{64}$ for the adversary, the protocol's data budget is:

$$\sigma \leq 2^{64.5} - 2^{64} \approx 2^{64} \text{ sponge blocks}$$

At 168 bytes per block, this is approximately $2^{64} \times 168 \approx 2^{71.4}$ bytes $\approx 2.8$ exabytes. This is the total data that can be processed across all operations in a single session (or globally, in the multi-user setting) while maintaining 128-bit security against an adversary with $2^{64}$ offline computation.

In practice, this limit is unreachable. For reference:

- 1 TB of encrypted data $\approx 2^{40}$ bytes $\approx 2^{33}$ sponge blocks
- 1 PB of encrypted data $\approx 2^{50}$ bytes $\approx 2^{43}$ sponge blocks
- The entire internet's daily traffic $\approx 2^{53}$ bytes $\approx 2^{46}$ sponge blocks

**Per-session recommendations.** Although the global data limit is enormous, implementations should enforce per-session limits as defense in depth:

- **Maximum message size per Seal/Mask:** No inherent limit beyond available memory, but implementations MAY enforce a limit of $2^{38}$ bytes (256 GB) per operation to bound per-invocation TreeWrap leaf count.

- **Maximum finalizations per session:** No inherent limit, but Ratchet at least every $2^{32}$ finalizations to limit the chain collision term and provide forward secrecy.

- **Session rekeying:** For sessions processing more than $2^{48}$ bytes cumulatively, rekey by establishing a new session with fresh key material. This is a conservative recommendation — the theoretical limit is far higher.

## 14. Typical Usage: AEAD

A standard AEAD construction:

```
Init("com.example.myprotocol")
Mix("key", key_material)
Mix("nonce", nonce)
Mix("ad", associated_data)
ciphertext ‖ tag ← Seal("message", plaintext)
```

Decryption:

```
Init("com.example.myprotocol")
Mix("key", key_material)
Mix("nonce", nonce)
Mix("ad", associated_data)
plaintext or ⊥ ← Open("message", ciphertext, tag)
```

## 15. References

- Backendal, M., Clermont, S., Fischlin, M., and Günther, F. "Key Derivation Functions Without a Grain of Salt." IACR ePrint 2025/657. Defines the RO-KDF construction requiring recoverable encoding.
- RFC 9861: TurboSHAKE and KangarooTwelve.
- NIST SP 800-185: SHA-3 Derived Functions (`left_encode`, `right_encode`).
- TreeWrap specification. Defines the tree-parallel stream cipher and MAC used by Mask and Seal.
- Daemen, J., Hoffert, S., Mella, S., Van Assche, G., and Van Keer, R. "Shaking up authenticated encryption." IACR ePrint 2024/1618.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." Defines CMT-4.

## 16. Test Vectors

(To be generated from a reference implementation.)

Recommended test cases:

- Init + Derive: Minimal protocol producing output.
- Init + Mix(key) + Mix(nonce) + Derive: Multiple non-finalizing operations before Derive.
- Init + Mix(key) + Seal(plaintext) + Derive: Full AEAD round-trip.
- Init + Mix(key) + Mask(plaintext) + Seal(plaintext): Combined unauthenticated and authenticated encryption.
- Init + Mix(key) + Ratchet + Derive: Forward secrecy — output differs from Derive without Ratchet.
- Fork with two branches each producing Derive: Independent outputs.
- Mix Stream with large input: Pre-hash commitment equivalence.
- Seal + Open with valid tag: Successful round-trip.
- Seal + Open with tampered ciphertext: Open returns ⊥, transcript still advances.
- Multiple Seals in sequence: Each key differs (transcript advances via tag absorption).
