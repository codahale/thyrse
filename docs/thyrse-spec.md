# Thyrse: A Transcript-Based Cryptographic Protocol Framework

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.5</td></tr>
  <tr><th>Date</th><td>2026-03-08</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

This document specifies Thyrse, a protocol framework that sequences cryptographic operations as frames appended to a
transcript. At each finalizing operation, KT128 (KangarooTwelve) is evaluated over the transcript to derive keys, chain
values, and pseudorandom output. The transcript encoding uses TKDF (see `tkdf-spec.md`), a recoverable encoding that
provides random-oracle-indifferentiable key derivation via the RO-KDF construction of Backendal, Clermont, Fischlin, and
Günther. Bulk encryption is delegated to TreeWrap when authenticated or unauthenticated ciphertext is needed.

The framework provides the following operations:

- **`Init`**: Establish a protocol identity.
- **`Mix`**: Absorb key material, nonces, or associated data. Data may be streamed without knowing its length in
  advance.
- **`Derive`**: Produce pseudorandom output that is a function of the full transcript.
- **`Ratchet`**: Irreversibly advance the protocol state for forward secrecy.
- **`Mask`** / **`Unmask`**: Encrypt or decrypt without authentication. The caller is responsible for authenticating the
  ciphertext through external mechanisms.
- **`Seal`** / **`Open`**: Encrypt or decrypt with authentication. `Open` rejects tampered ciphertext; the protocol
  state diverges naturally, permanently desynchronizing the instance.
- **`Fork`**: Clone the protocol state into independent branches with distinct identities.

All operations accept a label for domain separation. The full transcript is encoded with the TKDF recoverable encoding
(right-to-left parseable via position markers), as required by the RO-KDF proof.

## 2. Parameters

| Symbol | Value | Description                          |
|--------|-------|--------------------------------------|
| C      | 32    | TreeWrap key and tag size (bytes)    |
| H      | 64    | Chain value size (bytes)             |

## 3. Dependencies

**`KT128(M, S, ℓ)`:** KangarooTwelve as specified in RFC 9861. Takes a message `M`, a customization string `S`, and
an output length `ℓ` in bytes.

**`TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)`:** As specified in the TreeWrap specification. Takes a
`C`-byte key and arbitrary-length plaintext; returns same-length ciphertext and a `C`-byte tag.

**`TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)`:** Takes a `C`-byte key and arbitrary-length ciphertext;
returns same-length plaintext and a `C`-byte tag. TreeWrap does not perform tag verification; the caller is responsible
for comparing the returned tag against an expected value.

## 4. Integer Encoding

All integer encodings use `left_encode` and `right_encode` as defined in NIST SP 800-185.

**`left_encode(x)`** encodes a non-negative integer `x` as a byte string consisting of the length of the encoding (in
bytes) followed by the big-endian encoding of `x`. It is self-delimiting when parsed left-to-right. For example:

- `left_encode(0)` = `0x01 0x00`
- `left_encode(127)` = `0x01 0x7F`
- `left_encode(256)` = `0x02 0x01 0x00`

**`right_encode(x)`** encodes a non-negative integer `x` as a byte string consisting of the big-endian encoding of `x`
followed by the length of the encoding (in bytes). It is self-delimiting when parsed right-to-left. For example:

- `right_encode(0)` = `0x00 0x01`
- `right_encode(127)` = `0x7F 0x01`
- `right_encode(256)` = `0x01 0x00 0x02`

## 5. Encoding Convention

For a byte string `x`, we define:

**`encode_string(x)`** = `left_encode(len(x) × 8) ‖ x`

This is NIST SP 800-185's `encode_string`: the `left_encode` prefix encodes the bit-length of `x`, making the encoding
self-delimiting when parsed left-to-right.

### 5.1 Frame and Transcript Encoding

Each operation is encoded as a TKDF frame — a triple `(op, label, value)` — where `op` is a single byte, `label` is a
byte string, and `value` is a byte string of arbitrary length. The frame encoding is:

**`encode_frame(op, label, value)`** = `op ‖ encode_string(label) ‖ value`

Frames are concatenated into a transcript with `right_encode` position markers interleaved between them. The position
marker after each frame records the byte offset of the frame's start position:

**`encode_transcript(F₀, …, Fₘ₋₁)`** = `encode_frame(F₀) ‖ right_encode(s₀) ‖ ⋯ ‖ encode_frame(Fₘ₋₁) ‖ right_encode(sₘ₋₁)`

where `sᵢ` is the byte offset in the encoded transcript at which `encode_frame(Fᵢ)` begins (`s₀ = 0`).

The encoding can be constructed incrementally without knowing the length of any value in advance:

1. Record the current transcript length as `sᵢ`.
2. Append `op ‖ encode_string(label)`.
3. Stream the value as data becomes available.
4. When the operation completes, append `right_encode(sᵢ)`.

See `tkdf-spec.md` for the full specification, parse algorithm, and recoverability proof.

## 6. Customization Strings

Each KT128 evaluation uses a 1-byte customization string that identifies the purpose of the output:

| Byte | Purpose                        | Used by             |
|------|--------------------------------|---------------------|
| 0x20 | Chain value derivation         | Derive, Mask, Seal  |
| 0x21 | Derive output                  | Derive              |
| 0x22 | Mask key derivation            | Mask / Unmask       |
| 0x23 | Seal key derivation            | Seal / Open         |
| 0x24 | Ratchet chain derivation       | Ratchet             |

TreeWrap's internal domain bytes are not listed here; they are specified in the TreeWrap specification
and covered by its own security analysis.

## 7. Operation Codes

| Code | Operation | Finalizing |
|------|-----------|------------|
| 0x01 | INIT      | No         |
| 0x02 | MIX       | No         |
| 0x03 | FORK      | No         |
| 0x04 | DERIVE    | Yes        |
| 0x05 | RATCHET   | Yes        |
| 0x06 | MASK      | Yes        |
| 0x07 | SEAL      | Yes        |
| 0x08 | CHAIN     | No         |

## 8. Protocol State

The protocol state is a byte string called the **transcript**, initially empty. Operations append TKDF frames to the
transcript. Finalizing operations evaluate KT128 over the transcript and then reset it.

## 9. Security Requirements

### 9.1 Probabilistic Transcript

The confidentiality of `Mask` (IND-CPA) and `Seal` (IND-CCA2) depends on the TreeWrap key being indistinguishable from
random, which in turn requires the transcript at the point of finalization to contain at least one unpredictable input.
Callers MUST ensure that a fresh, unpredictable value (such as a nonce or ephemeral key) has been absorbed via `Mix`
before any `Mask` or `Seal` operation.

If two protocol runs reach the same transcript state and then `Mask` or `Seal` different plaintexts, they derive the
same TreeWrap key. This is catastrophic: TreeWrap with a repeated key leaks plaintext XOR differences, fully
compromising confidentiality.

This requirement is analogous to the nonce requirement of conventional AEAD schemes. It is the caller's responsibility
and is not enforced by the framework.

### 9.2 Derive Output Uniqueness

Similarly, `Derive` output is pseudorandom only if the transcript is unpredictable at the point of finalization. For use
cases where `Derive` serves as a random oracle (e.g., VOPRFs), the transcript MUST contain an unpredictable input. For
deterministic key derivation from known inputs, the output is a deterministic function of the transcript and is not
pseudorandom — it is a PRF output, which may still be sufficient depending on the application's security requirements.

## 10. Operations

All operations append TKDF frames as `(op, label, value)` triples. Position markers are managed by the transcript
machinery (§5.1). `T` denotes the encoded transcript.

### 10.1 Init

Establishes the protocol identity. The `Init` label provides protocol-level domain separation: two protocols using
different `Init` labels produce cryptographically independent transcripts even if all subsequent operations are
identical. See §11 for transcript validity requirements.

**`Init(label)`**

Append frame `(0x01, label, "")`.

### 10.2 Mix

Absorbs data into the protocol transcript. This is the default and preferred absorption operation for all inputs,
including key material, nonces, associated data, and any protocol input. Data may be streamed without knowing its length
in advance; the TKDF position marker closes the frame when the operation completes.

**`Mix(label, data)`**

Append frame `(0x02, label, data)`.

### 10.3 Fork

Clones the protocol state into `N` independent branches and modifies the base. Each branch receives a left-encoded
ordinal ID for domain separation. The base receives ordinal `0`; clones receive ordinals `1` through `N`.

**`Fork(label, values...) → clones[]`**

Let `N = len(values)` and let `T_snap` be the current transcript.

For the base (ordinal 0):

- Append frame `(0x03, label, left_encode(N) ‖ left_encode(0) ‖ encode_string(""))`

For each clone `i` (1 ≤ i ≤ N), create an independent protocol state from `T_snap` with:

- Append frame `(0x03, label, left_encode(N) ‖ left_encode(i) ‖ encode_string(values[i-1]))`

`Fork` does not finalize. All N+1 branches share the same transcript up to `T_snap` and diverge via their ordinals and
values.

Example: `Fork("role", "prover", "verifier")` produces three protocol states. The base continues with ordinal `0` and an
empty value. Clone 1 gets ordinal `1` with value `prover`. Clone 2 gets ordinal `2` with value `verifier`.

### 10.4 Derive

Produces pseudorandom output that is a deterministic function of the full transcript. Finalizes the current transcript
and begins a new one.

**`Derive(label, output_len) → output`**

Precondition: `output_len` MUST be greater than zero. Use `Ratchet` for zero-output-length state advancement.

1. Append frame `(0x04, label, left_encode(output_len))`.

2. Evaluate KT128 twice over the same transcript with different customization strings:

- `chain_value ← KT128(T, 0x20, H)`
- `output ← KT128(T, 0x21, output_len)`

3. Reset the transcript to a single frame:

- `(0x08, "", 0x04 ‖ left_encode(1) ‖ encode_string(chain_value))`

The two KT128 evaluations are independent and may execute in parallel.

Return `output`.

### 10.5 Ratchet

Irreversibly advances the protocol state. No user-visible output is produced.

**`Ratchet(label)`**

1. Append frame `(0x05, label, "")`.

2. Derive a chain value:

- `chain_value ← KT128(T, 0x24, H)`

3. Reset the transcript to a single frame:

- `(0x08, "", 0x05 ‖ left_encode(1) ‖ encode_string(chain_value))`

### 10.6 Mask / Unmask

Encrypts (`Mask`) or decrypts (`Unmask`) without authentication. Use `Mask` when integrity is provided by an external
mechanism (e.g., a signature over the transcript) or when confidentiality alone is sufficient.

**`Mask(label, plaintext) → ciphertext`**

1. Append frame `(0x06, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x22, C)`

3. Encrypt:

- `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`

4. Reset the transcript to a single frame:

- `(0x08, "", 0x06 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(tag))`

The two KT128 evaluations are independent and may execute in parallel.

Return `ciphertext`. The tag is not transmitted.

**`Unmask(label, ciphertext) → plaintext`**

1. Append frame (identical to `Mask`): `(0x06, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x22, C)`

3. Decrypt:

- `(plaintext, tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript to a single frame:

- `(0x08, "", 0x06 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(tag))`

Return `plaintext`.

*Warning:* Any application-level processing of the unmasked plaintext MUST be treated as untrusted and safely buffered
until an external authenticating operation (such as verifying a signature over a subsequent `Derive` output) has
succeeded.

### 10.7 Seal / Open

Encrypts (`Seal`) or decrypts (`Open`) with authentication. Use `Seal` when the ciphertext must be verified on receipt.
A failed `Open` indicates tampering; the protocol state diverges naturally because the receiver absorbs a different
computed tag than the sender, permanently desynchronizing the instance.

**`Seal(label, plaintext) → ciphertext ‖ tag`**

1. Append frame `(0x07, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x23, C)`

3. Encrypt:

- `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`

4. Reset the transcript to a single frame:

- `(0x08, "", 0x07 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(tag))`

The two KT128 evaluations are independent and may execute in parallel.

Return `ciphertext ‖ tag`.

**`Open(label, ciphertext, tag) → plaintext or ⊥`**

1. Append frame (identical to `Seal`): `(0x07, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x23, C)`

3. Decrypt:

- `(plaintext, computed_tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript (unconditionally) to a single frame:

- `(0x08, "", 0x07 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(computed_tag))`

5. Verify:

- If `computed_tag ≠ tag` (constant-time comparison), discard `plaintext` and return ⊥. The protocol state has
  diverged from the sender's state (because the CHAIN frame absorbed `computed_tag`, not the sender's `tag`) and
  subsequent operations will produce different results. The instance SHOULD be discarded.

Return `plaintext`.

### 10.8 Utility Operations

**`Clone() → copy`**

Returns an independent copy of the protocol state (transcript and, in sponge-based implementations, the full sponge
state and `Init` label). The original and clone evolve independently. `Clone` does not append a frame to the transcript.

*Warning:* Because `Clone` does not append a frame, applying identical operations to the original and the clone will
produce identical transcripts, potentially leading to catastrophic key reuse in `Mask` or `Seal`. Callers SHOULD use
`Fork` to
create independent protocol branches unless they are explicitly managing transcript divergence (e.g., repeating an
operation for benchmarking, or transferring state from sender to receiver).

**`Clear()`**

Overwrites the protocol state with zeros and invalidates the instance. Implementations MUST zero the sponge state, any
buffered key material, and the stored `Init` label. After `Clear`, the instance MUST NOT be used.

## 11. Recoverability

The transcript encoding is recoverable via the TKDF Parse algorithm (see `tkdf-spec.md` §6). Given an encoded
transcript, the Parse algorithm recovers the frame sequence by parsing position markers right-to-left. Each recovered
frame `(op, label, value)` can then be decomposed based on the operation code:

1. Parse the frame triple: `op` is the first byte, `label` is extracted from the `encode_string` prefix, and
   `value` is the remaining bytes.
2. Based on the operation code:

- **`INIT` (`0x01`):** `value` is empty.
- **`MIX` (`0x02`):** `value` is the raw data.
- **`FORK` (`0x03`):** `value` = `left_encode(N) ‖ left_encode(ordinal) ‖ encode_string(branch_value)`.
- **`DERIVE` (`0x04`):** `value` = `left_encode(output_len)`.
- **`RATCHET` (`0x05`):** `value` is empty.
- **`MASK` (`0x06`):** `value` is empty.
- **`SEAL` (`0x07`):** `value` is empty.
- **`CHAIN` (`0x08`):** `value` = `origin_op ‖ left_encode(n) ‖ encode_string(v₁) [‖ encode_string(v₂)]`.

Since `left_encode` and `encode_string` are self-delimiting, and the TKDF position markers provide frame boundaries,
the encoding is injective and recoverable. This satisfies the requirement of the RO-KDF construction.

**Transcript validity.** A valid transcript MUST begin with either an `INIT` frame (`0x01`) for the first instance or a
`CHAIN` frame (`0x08`) for subsequent instances after finalization. Implementations MUST reject any operation on an
empty transcript other than `Init`. A `CHAIN` origin byte MUST be one of `0x04`, `0x05`, `0x06`, `0x07`. Any other
leading byte or origin byte indicates a malformed transcript.

## 12. Implementation Notes

### 12.1 Sponge State Reuse

Although the transcript is described as a byte string that is hashed in its entirety at each finalization, an
implementation SHOULD maintain a running KT128 sponge state. Non-finalizing operations (`Init`, `Mix`, `Fork`) absorb
their frames incrementally into the sponge without forcing permutation boundaries. Finalizing operations clone the
sponge state and finalize the clones with their respective customization strings. This avoids re-hashing the full
transcript on each finalization.

The two KT128 evaluations at each finalization (chain value + output/key) require one clone and two independent
finalizations, which may execute in parallel on platforms with SIMD support for Keccak-p[1600,12].

### 12.2 Incremental Absorption

Multiple small Mix operations pack contiguously into the sponge rate (8192 bytes for KT128) with no forced permutation
boundaries. The sponge permutation occurs only when the rate buffer fills naturally. For a typical AEAD header — `Init`
+ `Mix(key)` + `Mix(nonce)` + `Mix(ad)` with a 32-byte key, 12-byte nonce, and 16-byte AD — the total frame size
(including position markers) is approximately 100 bytes, fitting within a single rate block with zero permutation calls
before encryption begins.

### 12.3 Constant-Time Operation

Implementations MUST ensure constant-time processing for all secret data. Tag verification in `Open` MUST use
constant-time comparison. TreeWrap key derivation and encryption MUST not branch on secret values.

### 12.4 Memory Sanitization

**Plaintext on failed `Open`.** `Open` decrypts ciphertext before verifying the tag. If verification fails, the
plaintext buffer contains unauthenticated data that MUST be zeroed before returning. Implementations that decrypt
in-place MUST overwrite the buffer with zeros (not with the original ciphertext, which may itself be
attacker-controlled). Callers MUST NOT read or act on plaintext from a failed `Open`.

**Protocol state.** The `Clear` operation (§10.8) zeros the sponge state, buffered key material, and stored `Init`
label. Implementations SHOULD also zero derived TreeWrap keys and intermediate chain values as soon as they are no
longer needed. For forward secrecy to hold after `Ratchet`, the pre-`Ratchet` sponge state MUST be erased; retaining it
in memory defeats the purpose of ratcheting.

**Language-level considerations.** In languages with garbage collection or compiler optimizations that may elide stores
to dead memory, implementations MUST use platform-specific secure-zeroing primitives (e.g., `explicit_bzero`,
`SecureZeroMemory`, `volatile` writes) to ensure that sensitive data is actually erased.

### 12.5 Practical Data Limits

The security bounds in §13.7 are expressed in terms of Keccak-p[1600,12] calls. This section converts
them to practical data volumes and provides operational recommendations.

**Sponge blocks per operation.** Each Keccak-p invocation processes one sponge block of `R = 168` bytes (TurboSHAKE128
rate, the inner hash function of KT128). The data complexity `σ` counts the total number of Keccak-p invocations across
all Thyrse backbone and TreeWrap operations:

- A `Mix` operation absorbing `d` bytes costs `⌈(frame overhead + d) / 168⌉` blocks, but
  since non-finalizing operations pack into the running sponge state, the cost is amortized. A typical
  AEAD header (`Init` + `Mix(key)` + `Mix(nonce)` + `Mix(ad)` with a 32-byte key, 12-byte nonce, and
  16-byte AD) fits within a single rate block with zero permutation calls before encryption begins.

- A finalizing operation (`Derive`, `Ratchet`, `Mask`, `Seal`) forces at least 2 Keccak-p calls (one per
  KT128 evaluation for the chain value and output/key clones).

- TreeWrap encryption of `m` bytes adds Keccak-p calls as specified in the TreeWrap specification. See
  the TreeWrap specification for per-invocation cost accounting.

**Data volume limits.** Setting a target of `ε_indiff ≤ 2⁻¹²⁸` in the
indifferentiability bound `2(σ + t)² / 2^(c+1)` gives `σ + t ≤ 2⁶⁴`. Assuming an
adversary offline budget of `t = 2⁶⁴`, the protocol's data budget is approximately `2⁶⁴` sponge
blocks, or approximately `2⁷¹` bytes (≈ 2.8 exabytes). This limit is shared across all operations in a
single session (or globally in the multi-user setting).

**Per-session recommendations.** Although the global data limit is enormous, implementations should enforce
per-session limits as defense in depth:

- **Maximum message size per `Seal`/`Mask`:** No inherent limit beyond available memory, but
  implementations MAY enforce a limit of `2³⁸` bytes (256 GB) per operation.

- **Maximum finalizations per session:** `Ratchet` at least every `2³²` finalizations to limit the
  chain collision term and provide forward secrecy.

- **Session rekeying:** For sessions processing more than `2⁴⁸` bytes cumulatively, rekey by
  establishing a new session with fresh key material.

## 13. Security Considerations

### 13.1 Assumptions

The security analysis relies on the following properties of Thyrse's underlying primitives. Each is
conditional on Keccak-p[1600,12] behaving as an ideal permutation at the claimed workloads.

**KT128.** KT128 is built on TurboSHAKE128 using Sakura encoding for tree hashing. TurboSHAKE128 is
indifferentiable from a random oracle under the ideal permutation model for Keccak-p[1600,12] (Bertoni,
Daemen, Peeters, Van Assche, 2008). The indifferentiability advantage is bounded by
`(σ + t)² / 2^(c+1)`, where `σ` is the total number of online Keccak-p calls, `t` is the adversary's
offline Keccak-p budget, and `c = 256` is the capacity in bits. KT128 inherits this bound with a Sakura
composition factor (see §13.7). KT128 evaluations with distinct customization strings are modeled as
independent random oracles, justified by the customization string occupying a structurally distinct position
in the final-node encoding (RFC 9861, §3.2).

**KT128 collision resistance.** Collision resistance of `H`-byte (64-byte) digests: 256-bit collision
resistance under the Keccak sponge claim, exceeding the 128-bit security target.

**TreeWrap.** Under a uniformly random `C`-byte key, TreeWrap provides:

- **IND-CPA** confidentiality (nonce-free: each key is used once).
- **INT-CTXT** authenticity, with forgery probability at most `S / 2^(8C)` for `S` attempts.
- **CMT-4** committing security: a ciphertext does not admit two valid openings under one key.
- **Tag PRF:** the full `C`-byte tag is a pseudorandom function of (key, ciphertext).

TreeWrap does not perform tag verification; the caller (Thyrse) is responsible. See the TreeWrap
specification for proofs of these properties.

### 13.2 Security Claims

The following table summarizes the security properties provided by each Thyrse operation. All
confidentiality and pseudorandomness claims require that the transcript contains at least one unpredictable
input (§9.1).

| Operation   | Property                      | Precondition                                      |
|-------------|-------------------------------|---------------------------------------------------|
| Derive      | PRF output                    | Unpredictable input in transcript                 |
| Ratchet     | Forward secrecy               | Prior sponge state erased (§12.4)                 |
| Mask/Unmask | IND-CPA confidentiality       | Unpredictable input in transcript                 |
| Seal/Open   | IND-CCA2 + CMT-4              | Unpredictable input in transcript                 |
| Fork        | Branch independence           | Distinct clone values                             |

Sections 13.4–13.6 establish these claims. Section 13.7 gives the concrete combined bound.

### 13.3 Domain Separation

All operation codes are in the range `0x01`–`0x08`. All KT128 customization strings used by the Thyrse
backbone are in the range `0x20`–`0x24`. These two ranges are disjoint.

Operation codes and customization strings serve structurally distinct roles: operation codes appear in the
transcript encoding (the message to KT128), while customization strings appear in the KT128 final-node
encoding as a suffix `S ‖ right_encode(|S|)` (RFC 9861, §3.2). No confusion between the two is possible
regardless of byte values.

The recoverable encoding (§11) ensures that distinct operation sequences produce distinct transcripts.
Combined with the customization string separation above, each KT128 evaluation in the protocol receives a
unique (message, customization string) pair, which maps to an independent random oracle output.

TreeWrap's internal domain bytes are specified in the TreeWrap specification and covered by its own domain
separation analysis. They do not appear in the Thyrse transcript and are not relevant to the Thyrse-level
security argument.

### 13.4 Per-Instance Security

Each transcript instance — from its initial `CHAIN` frame (or `INIT`, for Instance 0) through
finalization — is a single KT128 evaluation on a recoverably-encoded input. This matches the
RO-KDF construction of Backendal, Clermont, Fischlin, and Günther (Theorems 8 and 9 of ePrint 2025/657).

Under KT128's indifferentiability from a random oracle (§13.1), the RO-KDF proof gives: the
output of each finalization is indistinguishable from random as long as at least one input to the
transcript instance is unpredictable. In the notation of Backendal et al., the recoverable encoding
`⟨·⟩` is the TKDF encoding defined in `tkdf-spec.md`, and the source collection corresponds to the key
material, nonces, and chain values absorbed into the instance.

Two finalizations of the same transcript with different customization strings (e.g., chain value with
`0x20` and derived output with `0x21`) produce independent outputs. This follows from modeling KT128 with
distinct customization strings as independent random oracles (§13.1).

### 13.5 Composition Across Chain Boundaries

The RO-KDF proof (§13.4) covers a single KT128 evaluation. This section extends the argument
across chain boundaries, where one instance's chain value feeds into the next instance's transcript.

Consider Instance `k`, which finalizes with customization strings `0x20` (chain) and some output
customization string `D` (derive/key). Let `cv_k` denote the chain value and `out_k` denote the derived
output or key.

**Independence of chain value and output.** Since `cv_k` and `out_k` come from
independent random oracles on the same transcript (§13.4), they are independent. An adversary who observes
`out_k` (or ciphertext encrypted under a key derived from `out_k`) gains no information
about `cv_k`.

**Chain value as unpredictable source.** Instance `k+1` begins by absorbing the `CHAIN` frame
containing `cv_k`. In the random oracle model, `cv_k` is uniformly random — it is the
output of an RO on a transcript that the adversary has not queried, because doing so would require
predicting the unpredictable inputs to Instance `k`. Therefore `cv_k` satisfies the
unpredictability requirement of Theorem 8 in Backendal et al., and the RO-KDF proof applies to
Instance `k+1`.

**Tag absorption in `Mask`/`Seal` instances.** For `Mask` and `Seal` instances, the `CHAIN` frame also
absorbs the TreeWrap tag. The tag is a PRF of the TreeWrap key and the ciphertext (§13.1). Since the
TreeWrap key is derived from a different customization string than the chain value (e.g., `0x22` or `0x23`
vs. `0x20`), the key and chain value are independent. Therefore the tag — being a deterministic function of
the independent key and the public ciphertext — reveals no information about `cv_k`. The
composition argument is preserved.

**Induction.** By induction, the security of Instance `k+1` reduces to the security of Instance `k`
(via the pseudorandomness of `cv_k`), which ultimately reduces to the unpredictability of the
original key material in Instance 0.

**Chain value collisions.** Each chain value is `H = 64` bytes (512 bits). The birthday bound for chain
value collisions across `q` instances is `q² / 2^(8H+1) = q² / 2⁵¹³`. A collision would cause two
instances to share identical subsequent transcripts. For `q ≤ 2⁴⁸`, this probability
is `2⁻⁴¹⁷`, far below the 128-bit security target.

### 13.6 Operation-Specific Arguments

**Derive.** Direct application of §13.4. The output is produced by KT128 with customization string `0x21`
on the current transcript. Under the RO-KDF argument, this output is indistinguishable from random given
an unpredictable input in the transcript.

**Ratchet.** The chain value (customization string `0x24`) is the sole output. The pre-ratchet transcript
is unrecoverable from the chain value by KT128 preimage resistance. Forward secrecy holds provided
the implementation erases the pre-ratchet sponge state from memory (§12.4). Without erasure, an adversary
who compromises the post-ratchet state and retains access to the pre-ratchet sponge state can recover
prior keys.

**Mask / Unmask.** The TreeWrap key is derived via KT128 with customization string `0x22` on the current
transcript. Under the RO-KDF argument (§13.4), this key is indistinguishable from a uniformly random
`C`-byte string as long as the transcript contains an unpredictable input. By the TreeWrap IND-CPA
assumption (§13.1), `Mask` provides IND-CPA confidentiality.

The tag absorbed into the `CHAIN` frame is independent of the chain value, preserving composition
(§13.5). If the ciphertext is tampered with, the sender and receiver compute different tags, causing their
transcripts to diverge and all subsequent operations to produce different results. However, `Mask` alone
does not provide integrity guarantees. Applications requiring integrity should use `Seal` or authenticate
the ciphertext externally (e.g., via a signature over a subsequent `Derive` output).

**Seal / Open.** The TreeWrap key is derived via customization string `0x23`. The same RO-KDF argument
gives a key indistinguishable from random. By the TreeWrap IND-CPA and INT-CTXT assumptions (§13.1),
`Seal` provides IND-CCA2 security via generic composition (Bellare and Namprempre, ASIACRYPT 2000):
IND-CPA + INT-CTXT implies IND-CCA2. CMT-4 committing security follows from TreeWrap's CMT-4 claim
(§13.1).

`Open` advances the transcript unconditionally with the computed tag. On verification failure, the
receiver's computed tag differs from the sender's, and the `CHAIN` frame absorbs a different value. This
permanently desynchronizes the protocol state: all subsequent operations produce different results. After
a failed `Open`, the protocol instance SHOULD be discarded.

**Fork.** `Fork` does not finalize. All `N+1` branches share identical transcript up to the fork point
and diverge via their ordinals and (for clones) branch-specific values. The ordinal alone ensures the base
is distinct from all clones. Since the encoding is injective (§11), distinct ordinals or values produce
distinct transcripts, guaranteeing independent outputs at any subsequent finalization. Callers MUST ensure
clone values are distinct from each other.

### 13.7 Concrete Security Bound

This section gives the combined security bound for the Thyrse framework. The reduction has three layers:
replace the sponge with a random oracle (indifferentiability), apply the RO-KDF argument per instance with
inductive composition (§§13.4–13.5), and invoke TreeWrap's security as a black box (§13.1).

**Parameters.**

| Symbol   | Meaning                                                                       |
|----------|-------------------------------------------------------------------------------|
| `q`      | Total number of finalizing operations across the protocol lifetime            |
| `σ`      | Total data complexity: number of Keccak-p[1600,12] calls made by the protocol |
| `t`      | Adversary's offline computation budget in Keccak-p[1600,12] calls             |
| `S`      | Number of forgery attempts against `Seal`/`Open`                              |
| `c`      | TurboSHAKE128 capacity = 256 bits                                             |
| `H`      | Chain value length = 512 bits                                                 |

The data complexity `σ` counts all Keccak-p calls made by Thyrse backbone operations (KT128
finalizations) and by TreeWrap encryption/decryption. Although TreeWrap's security is
analyzed separately, its Keccak-p calls share the same ideal permutation and therefore contribute to the
global indifferentiability budget.

**Combined bound.**

$$\varepsilon_{\mathrm{total}} \leq \varepsilon_{\mathrm{perm}} + \frac{2(\sigma + t)^2}{2^{c+1}} + q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{q^2}{2^{8H+1}} + \varepsilon_{\mathrm{tw}}$$

where:

- `ε_perm` is the advantage of distinguishing Keccak-p[1600,12] from a random
  permutation (conjectured negligible).
- `2(σ + t)² / 2^(c+1) = 2(σ + t)² / 2²⁵⁷` is the sponge indifferentiability term, covering
  all Keccak-p evaluations globally (Thyrse backbone and TreeWrap internals). The factor of 2 arises from
  the Sakura composition: the combined indifferentiability of KT128 (tree hash on TurboSHAKE128) is bounded
  by `q_tree² / 2^(c+1) + (σ + t)² / 2^(c+1)`, which simplifies to `2(σ + t)² / 2^(c+1)` since
  `q_tree ≤ σ`.
- `q · ε_kdf(0)` is `q` times the per-instance RO-KDF bound, which depends on
  the unpredictability of the caller's key material. For key material with `κ` bits of min-entropy,
  `ε_kdf(0) ≤ 2 · t / 2^κ`.
- `q² / 2^(8H+1) = q² / 2⁵¹³` bounds chain value collisions (§13.5).
- `ε_tw` is TreeWrap's per-invocation security advantage, treated as a black-box
  term. See the TreeWrap specification (§6.11) for the concrete bound; the dominant term is
  `S / 2^(8C) = S / 2²⁵⁶` for forgery resistance.

**Numerical evaluation.** For typical parameters — `q ≤ 2⁴⁸` finalizations,
`σ + t ≤ 2⁶⁴` total Keccak-p calls, `S ≤ 2⁴⁸` forgery attempts, and 256-bit key
material (`κ = 256`):

- Indifferentiability: `2(2⁶⁴)² / 2²⁵⁷ = 2⁻¹²⁸`
- RO-KDF: `2⁴⁸ · 2 · 2⁶⁴ / 2²⁵⁶ = 2⁻¹⁴³`
- Chain collisions: `(2⁴⁸)² / 2⁵¹³ = 2⁻⁴¹⁷`
- TreeWrap forgery: `2⁴⁸ / 2²⁵⁶ = 2⁻²⁰⁸`

The indifferentiability term dominates. The 128-bit security target is met as long as the caller ensures
`ε_kdf(0) ≤ 2⁻¹²⁸` (i.e., the original key material has at least 128 bits of
min-entropy) and the total data complexity satisfies `σ + t ≤ 2⁶⁴`.

### 13.8 Multi-User Security

The bound in §13.7 covers a single protocol session. In a multi-user setting with `U` independent sessions
(each with an independent key), the adversary's advantage increases because it can target any session.

**Multi-user indifferentiability.** The sponge indifferentiability term is a global resource shared across
all sessions. If the adversary makes `t` offline Keccak-p queries and the `U` sessions collectively
process `σ_total` Keccak-p calls, the indifferentiability term is:

$$\varepsilon_{\mathrm{indiff}} \leq \frac{2(\sigma_{\mathrm{total}} + t)^2}{2^{257}}$$

The adversary does not gain a per-user multiplier because indifferentiability is a global property of the
permutation.

**Multi-user key recovery.** The adversary can attempt to recover any of the `U` session keys. Under the
RO-KDF argument, each session key is derived from a KT128 evaluation on a transcript containing
unpredictable key material. This gives a multi-target advantage of:

$$\varepsilon_{\mathrm{mu\text{-}key}} \leq U \cdot \varepsilon_{\mathrm{kdf}}(0)$$

For 256-bit key material and an adversary with budget `t = 2⁶⁴` across `U = 2³²` users:
`ε_mu-key ≈ 2³² · 2⁶⁴ / 2²⁵⁶ = 2⁻¹⁶⁰`.

**Multi-user chain collisions.** The probability of a cross-session chain collision is:

$$\varepsilon_{\mathrm{mu\text{-}chain}} \leq \frac{(U \cdot q)^2}{2^{513}}$$

For `U = 2³²` sessions with `q = 2³²` finalizations each:
`(2⁶⁴)² / 2⁵¹³ = 2⁻³⁸⁵`.

**Multi-user forgery.** The total forgery advantage across all sessions is `S / 2²⁵⁶`, where `S` is the
total number of forgery attempts.

**Combined multi-user bound:**

$$\varepsilon_{\mathrm{mu\text{-}total}} \leq \varepsilon_{\mathrm{perm}} + \frac{2(\sigma_{\mathrm{total}} + t)^2}{2^{257}} + U \cdot q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{(U \cdot q)^2}{2^{513}} + \frac{S}{2^{256}}$$

**Ratcheting as mitigation.** After a `Ratchet` operation, the session state contains only a chain
value — a 512-bit pseudorandom string with no algebraic structure exploitable in a multi-target search.
An adversary targeting pre-ratchet key material must do so before the ratchet occurs. If a session
ratchets every `W` finalizing operations, the adversary must target a specific epoch rather than the full
session lifetime. Ratcheting does not improve the initial key recovery bound, but it ensures that
compromising any single epoch does not compromise the full session (forward secrecy, §13.6). For
long-lived sessions, periodic ratcheting every few hundred operations is recommended.

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

- Backendal, M., Clermont, S., Fischlin, M., and Günther, F. "Key Derivation Functions Without a Grain
  of Salt." IACR ePrint 2025/657. Defines the RO-KDF construction requiring recoverable encoding.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing."
  IACR ePrint 2013/231. Applied Cryptography and Network Security (ACNS) 2014. Defines and proves
  soundness of the Sakura tree hash coding convention.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B. "KangarooTwelve:
  fast hashing based on Keccak-p." IACR ePrint 2016/770. Applied Cryptography and Network Security
  (ACNS) 2018. Specifies KT128 as a concrete application of Sakura encoding.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "On the Indifferentiability of the Sponge
  Construction." IACR ePrint 2008/014. Eurocrypt 2008. Proves sponge indifferentiability from a random
  oracle under the ideal permutation model.
- Maurer, U., Renner, R., and Holenstein, C. "Indifferentiability, Impossibility Results on Reductions, and
  Applications to the Random Oracle Methodology." TCC 2004. Defines indifferentiability and proves the
  composition theorem.
- NIST SP 800-185: SHA-3 Derived Functions (`left_encode`, `right_encode`, `encode_string`).
- RFC 9861: KangarooTwelve and TurboSHAKE.
- TreeWrap128 specification. Defines the tree-parallel authenticated encryption scheme used by Mask and
  Seal. Provides IND-CPA, INT-CTXT, CMT-4, and tag PRF security claims referenced in §13.1.
- Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the
  Generic Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." EUROCRYPT
  2022. Defines the CMT-4 committing security notion.

## 16. Test Vectors

All values are hex-encoded. All test vectors use `Init` label `"test.vector"`. Byte string literals are shown in hex as
`(hex)`.

### 16.1 Init + Derive

Minimal protocol producing output.

```
Init("test.vector")
Derive("output", 32)
```

| Field         | Value                                                              |
|---------------|--------------------------------------------------------------------|
| Derive output | `25feba088971a4b573101369ea1c8d83e6f102c2dc46e5cceb81a0b97fca514c` |

### 16.2 Init + Mix + Mix + Derive

Multiple non-finalizing operations before `Derive`.

```
Init("test.vector")
Mix("key", "test-key-material")
Mix("nonce", "test-nonce-value")
Derive("output", 32)
```

| Field         | Value                                                              |
|---------------|--------------------------------------------------------------------|
| key data      | `746573742d6b65792d6d6174657269616c`                               |
| nonce data    | `746573742d6e6f6e63652d76616c7565`                                 |
| Derive output | `0db4090efec2ba935dac63a18d88df04859d1dedf4a60f428393674520b67e39` |

### 16.3 Init + Mix + Seal + Derive

Full AEAD followed by `Derive`.

```
Init("test.vector")
Mix("key", "test-key-material")
Seal("message", "hello, world!")
Derive("output", 32)
```

| Field                  | Value                                                                                        |
|------------------------|----------------------------------------------------------------------------------------------|
| key data               | `746573742d6b65792d6d6174657269616c`                                                         |
| plaintext              | `68656c6c6f2c20776f726c6421`                                                                 |
| Seal output (ct ‖ tag) | `dde795eebaaa663b55e904c1e4da1c6c6f1c770b9c90fd17b8add38741dd5e4c821ad0e5aeb4bbfbc18d89ebe4` |
| Derive output          | `e6a99cd5ac77af8370dd09e5f1ea020b1ded0a7415a9dadcbe6133e917dd2498`                           |

### 16.4 Init + Mix + Mask + Seal

Combined unauthenticated and authenticated encryption.

```
Init("test.vector")
Mix("key", "test-key-material")
Mask("unauthenticated", "mask this data")
Seal("authenticated", "seal this data")
```

| Field                  | Value                                                                                          |
|------------------------|------------------------------------------------------------------------------------------------|
| key data               | `746573742d6b65792d6d6174657269616c`                                                           |
| Mask plaintext         | `6d61736b20746869732064617461`                                                                 |
| Mask output (ct)       | `21fc87f3008b3cff62fb2584c970`                                                                 |
| Seal plaintext         | `7365616c20746869732064617461`                                                                 |
| Seal output (ct ‖ tag) | `f078ea89c7dea34a821c8470544ec5a70061c75aa9de8a1d49e4a9e816455ca54f78e50a2a1981d1c0a47cfe4d20` |

### 16.5 Init + Mix + Ratchet + Derive

Forward secrecy: output differs from `Derive` without `Ratchet`.

```
Init("test.vector")
Mix("key", "test-key-material")
Derive("output", 32)                     # without Ratchet

Init("test.vector")
Mix("key", "test-key-material")
Ratchet("forward-secrecy")
Derive("output", 32)                     # with Ratchet
```

| Field                  | Value                                                              |
|------------------------|--------------------------------------------------------------------|
| key data               | `746573742d6b65792d6d6174657269616c`                               |
| Derive (no Ratchet)    | `b20333efd472bf1cafbdfcc7c4aef46ca9984b768dbf84e33006024bead07dcf` |
| Derive (after Ratchet) | `23be92e694890a8b3d6fb5b4885b3b5a63539ad8da6fc5e8e20cf34728dbeb91` |

### 16.6 Fork + Derive

`Fork` with two branches, each producing `Derive`. All three outputs are independent.

```
Init("test.vector")
Mix("key", "test-key-material")
Fork("role", "prover", "verifier")       # base = ordinal 0, clone 1 = "prover", clone 2 = "verifier"
Derive("output", 32)                     # on each branch
```

| Branch                       | Derive output                                                      |
|------------------------------|--------------------------------------------------------------------|
| Base (ordinal 0)             | `53fa58633361a67384c7a6d8df0e6163dac581024e9786856442edf13e5b787c` |
| Clone 1 / "prover" (ord 1)   | `329696ce84ae7aef8577db9841d82956b60f9f7ce38449d8b83092f3a46a89ad` |
| Clone 2 / "verifier" (ord 2) | `19644cc5d0a5bc8f52eb647a581b85ba868ce0cb3561f8d2a58f1bf6ed1a3e82` |

### 16.7 Seal + Open Round-Trip

Successful authenticated encryption and decryption. Post-operation `Derive` outputs match.

```
Init("test.vector")
Mix("key", "test-key-material")
Mix("nonce", "test-nonce-value")
Mix("ad", "associated data")
Seal("message", "hello, world!")         # sender
Open("message", <sealed>)               # receiver
Derive("confirm", 32)                   # both sides
```

| Field                          | Value                                                                                        |
|--------------------------------|----------------------------------------------------------------------------------------------|
| ad data                        | `6173736f6369617465642064617461`                                                             |
| plaintext                      | `68656c6c6f2c20776f726c6421`                                                                 |
| Seal output (ct ‖ tag)         | `1383ffe1d63304655b9b94ae27f2a50ea1734e2df148381c2080d70ad86bac40e84d08e43b48b0b9f4a106156a` |
| Open plaintext                 | `68656c6c6f2c20776f726c6421`                                                                 |
| Derive("confirm") — both sides | (matches between sender and receiver)                                                        |

### 16.8 Seal + Open with Tampered Ciphertext

`Open` returns ⊥. Transcripts desynchronize: subsequent `Derive` outputs diverge.

```
Init("test.vector")
Mix("key", "test-key-material")
Mix("nonce", "test-nonce-value")
Seal("message", "hello, world!")         # sender
Open("message", <tampered>)             # receiver — tampered[0] ^= 0xff
Derive("after", 32)                     # both sides
```

| Field                                | Value                                                                                        |
|--------------------------------------|----------------------------------------------------------------------------------------------|
| Seal output                          | `6e73c8fb8e615ac7d3bfdeaaa7e8e1af189b97db42b2870b693c5faf0be6bbc8345d8830401a53acccc756500a` |
| Tampered (first byte XOR 0xff)       | `9173c8fb8e615ac7d3bfdeaaa7e8e1af189b97db42b2870b693c5faf0be6bbc8345d8830401a53acccc756500a` |
| Open result                          | ⊥ (authentication failed)                                                                    |

### 16.9 Multiple Seals in Sequence

Each `Seal` derives a different key because the transcript advances via tag absorption.

```
Init("test.vector")
Mix("key", "test-key-material")
Mix("nonce", "test-nonce-value")
Seal("msg", "first message")
Seal("msg", "second message")
Seal("msg", "third message")
```

| Seal | Plaintext (hex)                | Output (ct ‖ tag)                                                                              |
|------|--------------------------------|------------------------------------------------------------------------------------------------|
| 1    | `6669727374206d657373616765`   | `f58f5895735ec5679a75651160f0e2b29ea495e5a13e482d22c5bd1f58c75a345a9dacbf4205022b27f809fcc2`   |
| 2    | `7365636f6e64206d657373616765` | `2b6b64822aa4ac6716aaf6226e20d4d9f1c6ac6bafbe00761b03663b3e574d91be5fa8918945fa311214cfa83e1b` |
| 3    | `7468697264206d657373616765`   | `86de20dad1084ed184d23aa56a3c3001a468b67c6687b2ab93e5b640008b6c912f88b6a3a88cd4283a7719c273`   |
