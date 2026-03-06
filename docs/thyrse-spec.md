# Thyrse: A Transcript-Based Cryptographic Protocol Framework

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.4</td></tr>
  <tr><th>Date</th><td>2026-02-28</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

This document specifies Thyrse, a protocol framework that sequences cryptographic operations as frames appended to a
transcript. At each finalizing operation, TurboSHAKE128 is evaluated over the transcript to derive keys, chain values,
and pseudorandom output. The transcript encoding is recoverable, providing random-oracle-indifferentiable key derivation
via the RO-KDF construction of Backendal, Clermont, Fischlin, and Günther. Bulk encryption is delegated to TreeWrap when
authenticated or unauthenticated ciphertext is needed.

The framework provides the following operations:

- **`Init`**: Establish a protocol identity.
- **`Mix`**: Absorb key material, nonces, or associated data.
- **`MixDigest`**: Absorb data too large to fit in memory, via KT128 pre-hashing. Suitable only for inputs that may
  exceed 8 KiB; if the input length is known in advance and is less than 8 KiB, use `Mix` instead.
- **`Derive`**: Produce pseudorandom output that is a function of the full transcript.
- **`Ratchet`**: Irreversibly advance the protocol state for forward secrecy.
- **`Mask`** / **`Unmask`**: Encrypt or decrypt without authentication. The caller is responsible for authenticating the
  ciphertext through external mechanisms.
- **`Seal`** / **`Open`**: Encrypt or decrypt with authentication. `Open` rejects tampered ciphertext and terminates the
  protocol instance.
- **`Fork`**: Clone the protocol state into independent branches with distinct identities.

All operations accept a label for domain separation. The full transcript is encoded with a recoverable (left-to-right
parseable) encoding, as required by the RO-KDF proof.

## 2. Parameters

| Symbol | Value | Description                                  |
|--------|-------|----------------------------------------------|
| C      | 32    | TreeWrap key and tag size (bytes)            |
| H      | 64    | Chain value and pre-hash digest size (bytes) |

## 3. Dependencies

**`TurboSHAKE128(M, D, ℓ)`:** As specified in RFC 9861. Takes a message `M`, a domain separation byte `D`
(0x01 – 0x7F), and an output length `ℓ` in bytes.

**`KT128(M, S, ℓ)`:** KangarooTwelve as specified in RFC 9861. Takes a message `M`, a customization string `S`, and
an output length `ℓ` in bytes.

**`TreeWrap.EncryptAndMAC(key, plaintext) → (ciphertext, tag)`:** As specified in the TreeWrap specification. Takes a
`C`-byte key and arbitrary-length plaintext; returns same-length ciphertext and a `C`-byte tag.

**`TreeWrap.DecryptAndMAC(key, ciphertext) → (plaintext, tag)`:** Takes a `C`-byte key and arbitrary-length ciphertext;
returns same-length plaintext and a `C`-byte tag. TreeWrap does not perform tag verification; the caller is responsible
for comparing the returned tag against an expected value.

## 4. Integer Encoding

All integer encodings use `left_encode` as defined in NIST SP 800-185, consistent with KangarooTwelve. `left_encode(x)`
encodes a non-negative integer `x` as a byte string consisting of the length of the encoding (in bytes) followed by the
big-endian encoding of `x`. For example:

- `left_encode(0)` = `0x01 0x00`
- `left_encode(127)` = `0x01 0x7F`
- `left_encode(256)` = `0x02 0x01 0x00`

## 5. Encoding Convention

For a byte string `x`, we define:

**`length_encode(x)`** = `left_encode(len(x)) ‖ x`

This encoding is self-delimiting when parsed left-to-right: the `left_encode` prefix determines the length of `x`, and
the subsequent `len(x)` bytes are `x` itself. A concatenation of `length_encode` values is therefore recoverable — a
parser can unambiguously extract each element.

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

All domain bytes are in the range 0x01–0x7F as required by TurboSHAKE128. TreeWrap's internal domain
bytes are not listed here; they are specified in the TreeWrap specification and covered by its own
security analysis.

## 7. Operation Codes

| Code | Operation  | Finalizing |
|------|------------|------------|
| 0x10 | INIT       | No         |
| 0x11 | MIX        | No         |
| 0x12 | MIX_DIGEST | No         |
| 0x13 | FORK       | No         |
| 0x14 | DERIVE     | Yes        |
| 0x15 | RATCHET    | Yes        |
| 0x16 | MASK       | Yes        |
| 0x17 | SEAL       | Yes        |
| 0x18 | CHAIN      | No         |

## 8. Protocol State

The protocol state is a byte string called the **transcript**, initially empty. Operations append frames to the
transcript. Finalizing operations evaluate TurboSHAKE128 over the transcript and then reset it.

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

### 10.1 Init

Establishes the protocol identity. The `Init` label provides protocol-level domain separation: two protocols using
different `Init` labels produce cryptographically independent transcripts even if all subsequent operations are
identical. See §11 for transcript validity requirements.

**`Init(label)`**

- `transcript ← 0x10 ‖ length_encode(label)`

### 10.2 Mix

Absorbs data into the protocol transcript. This is the default and preferred absorption operation for the vast majority
of inputs, including key material, nonces, associated data, and any protocol input whose length is known in advance to
be less than 8 KiB. `Mix` absorbs data directly into the running sponge state with no pre-hashing overhead.

**`Mix(label, data)`**

- `transcript ← transcript ‖ 0x11 ‖ length_encode(label) ‖ length_encode(data)`

### 10.3 Mix Digest

Absorbs data that may not fit in memory by pre-hashing it through KT128 to produce a fixed-size commitment. The `Init`
label is used as the KT128 customization string, binding the digest to the protocol identity.

`MixDigest` is suitable only for inputs that may exceed 8 KiB in size. KT128 pre-hashing incurs significant overhead
compared to direct absorption: it requires a full KT128 evaluation over the input data before the digest can be
absorbed, roughly doubling the cost per byte relative to `Mix`. If the input length is known in advance and is less than
8 KiB, callers SHOULD use `Mix` instead, which absorbs data directly into the sponge state with no pre-hashing overhead.

**`MixDigest(label, data)`**

- `digest ← KT128(data, init_label, H)`
- `transcript ← transcript ‖ 0x12 ‖ length_encode(label) ‖ length_encode(digest)`

Here `init_label` is the label passed to the `Init` operation that established this protocol instance. Implementations
MUST retain this value for the lifetime of the instance.

### 10.4 Fork

Clones the protocol state into `N` independent branches and modifies the base. Each branch receives a left-encoded
ordinal ID for domain separation. The base receives ordinal `0`; clones receive ordinals `1` through `N`.

**`Fork(label, values...) → clones[]`**

Let `N = len(values)` and let `t` be the current value of `transcript`.

For the base (ordinal 0):

- `transcript ← t ‖ 0x13 ‖ length_encode(label) ‖ left_encode(N) ‖ left_encode(0) ‖ length_encode("")`

For each clone `i` (1 ≤ i ≤ N), create an independent protocol state with:

- `transcript ← t ‖ 0x13 ‖ length_encode(label) ‖ left_encode(N) ‖ left_encode(i) ‖ length_encode(values[i-1])`

`Fork` does not finalize. All N+1 branches share the same transcript up to `t` and diverge via their ordinals and
values.

Example: `Fork("role", "prover", "verifier")` produces three protocol states. The base continues with ordinal `0` and an
empty value. Clone 1 gets ordinal `1` with value `prover`. Clone 2 gets ordinal `2` with value `verifier`.

### 10.5 Derive

Produces pseudorandom output that is a deterministic function of the full transcript. Finalizes the current transcript
and begins a new one.

**`Derive(label, output_len) → output`**

Precondition: `output_len` MUST be greater than zero. Use `Ratchet` for zero-output-length state advancement.

1. Append the frame:

- `transcript ← transcript ‖ 0x14 ‖ length_encode(label) ‖ left_encode(output_len)`

2. Evaluate TurboSHAKE128 twice over the same transcript with different domain bytes:

- `chain_value ← TurboSHAKE128(transcript, 0x20, H)`
- `output ← TurboSHAKE128(transcript, 0x21, output_len)`

3. Reset the transcript:

- `transcript ← 0x18 ‖ 0x14 ‖ left_encode(1) ‖ length_encode(chain_value)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `output`.

### 10.6 Ratchet

Irreversibly advances the protocol state. No user-visible output is produced.

**`Ratchet(label)`**

1. Append the frame:

- `transcript ← transcript ‖ 0x15 ‖ length_encode(label)`

2. Derive a chain value:

- `chain_value ← TurboSHAKE128(transcript, 0x24, H)`

3. Reset the transcript:

- `transcript ← 0x18 ‖ 0x15 ‖ left_encode(1) ‖ length_encode(chain_value)`

### 10.7 Mask / Unmask

Encrypts (`Mask`) or decrypts (`Unmask`) without authentication. Use `Mask` when integrity is provided by an external
mechanism (e.g., a signature over the transcript) or when confidentiality alone is sufficient.

**`Mask(label, plaintext) → ciphertext`**

1. Append the frame:

- `transcript ← transcript ‖ 0x16 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

- `chain_value ← TurboSHAKE128(transcript, 0x20, H)`
- `key ← TurboSHAKE128(transcript, 0x22, C)`

3. Encrypt:

- `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`

4. Reset the transcript:

- `transcript ← 0x18 ‖ 0x16 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `ciphertext`. The tag is not transmitted.

**`Unmask(label, ciphertext) → plaintext`**

1. Append the frame (identical to `Mask`):

- `transcript ← transcript ‖ 0x16 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

- `chain_value ← TurboSHAKE128(transcript, 0x20, H)`
- `key ← TurboSHAKE128(transcript, 0x22, C)`

3. Decrypt:

- `(plaintext, tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript:

- `transcript ← 0x18 ‖ 0x16 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

Return `plaintext`.

*Warning:* Any application-level processing of the unmasked plaintext MUST be treated as untrusted and safely buffered
until an external authenticating operation (such as verifying a signature over a subsequent `Derive` output) has
succeeded.

### 10.8 Seal / Open

Encrypts (`Seal`) or decrypts (`Open`) with authentication. Use `Seal` when the ciphertext must be verified on receipt.
A failed `Open` indicates tampering and permanently invalidates the protocol instance.

**`Seal(label, plaintext) → ciphertext ‖ tag`**

1. Append the frame:

- `transcript ← transcript ‖ 0x17 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

- `chain_value ← TurboSHAKE128(transcript, 0x20, H)`
- `key ← TurboSHAKE128(transcript, 0x23, C)`

3. Encrypt:

- `(ciphertext, tag) ← TreeWrap.EncryptAndMAC(key, plaintext)`

4. Reset the transcript:

- `transcript ← 0x18 ‖ 0x17 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(tag)`

The two TurboSHAKE128 evaluations are independent and may execute in parallel.

Return `ciphertext ‖ tag`.

**`Open(label, ciphertext, tag) → plaintext or ⊥`**

1. Append the frame (identical to `Seal`):

- `transcript ← transcript ‖ 0x17 ‖ length_encode(label)`

2. Evaluate TurboSHAKE128 twice:

- `chain_value ← TurboSHAKE128(transcript, 0x20, H)`
- `key ← TurboSHAKE128(transcript, 0x23, C)`

3. Decrypt:

- `(plaintext, computed_tag) ← TreeWrap.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript (unconditionally):

- `transcript ← 0x18 ‖ 0x17 ‖ left_encode(2) ‖ length_encode(chain_value) ‖ length_encode(computed_tag)`

5. Verify:

- If `computed_tag ≠ tag` (constant-time comparison), discard `plaintext` and return ⊥. The protocol instance is
  permanently desynchronized and MUST be discarded immediately.

Return `plaintext`.

### 10.9 Utility Operations

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

The encoding of every operation frame is recoverable by left-to-right parsing. Given a transcript byte string, a parser
can unambiguously extract each operation:

1. Read one byte: the operation code.
2. Based on the operation code:

- **`INIT` (`0x10`):** Parse `length_encode(label)`.
- **`MIX` (`0x11`):** Parse `length_encode(label)`, then `length_encode(data)`.
- **`MIX_DIGEST` (`0x12`):** Parse `length_encode(label)`, then `length_encode(digest)`.
- **`FORK` (`0x13`):** Parse `length_encode(label)`, then `left_encode(N)`, then `left_encode(ordinal)`, then
  `length_encode(value)`.
- **`DERIVE` (`0x14`):** Parse `length_encode(label)`, then `left_encode(output_len)`.
- **`RATCHET` (`0x15`):** Parse `length_encode(label)`.
- **`MASK` (`0x16`):** Parse `length_encode(label)`.
- **`SEAL` (`0x17`):** Parse `length_encode(label)`.
- **`CHAIN` (`0x18`):** Read one byte: the origin operation code (`0x14`, `0x15`, `0x16`, or `0x17`). Parse
  `left_encode(n)`, then parse `n` instances of `length_encode(value)`.

3. The next byte is the operation code of the subsequent operation, or the transcript ends.

Since `left_encode` is self-delimiting and all variable-length fields are length-prefixed, the encoding is injective and
recoverable. This satisfies the requirement of the RO-KDF construction.

**Transcript validity.** A valid transcript MUST begin with either an `INIT` frame (`0x10`) for the first instance or a
`CHAIN` frame (`0x18`) for subsequent instances after finalization. Implementations MUST reject any operation on an
empty transcript other than `Init`. A `CHAIN` origin byte MUST be one of `0x14`, `0x15`, `0x16`, `0x17`. Any other
leading byte or origin byte indicates a malformed transcript.

## 12. Implementation Notes

### 12.1 Sponge State Reuse

Although the transcript is described as a byte string that is hashed in its entirety at each finalization, an
implementation SHOULD maintain a running TurboSHAKE128 sponge state. Non-finalizing operations (`Init`, `Mix`,
`MixDigest`, `Fork`) absorb their frames incrementally into the sponge without forcing permutation boundaries.
Finalizing operations clone the sponge state and finalize the clones with their respective domain bytes. This avoids
re-hashing the full transcript on each finalization.

The two TurboSHAKE128 evaluations at each finalization (chain value + output/key) require one clone and two independent
finalizations, which may execute in parallel on platforms with SIMD support for Keccak-p[1600,12].

### 12.2 Incremental Absorption

Multiple small Mix operations pack contiguously into the sponge rate (168 bytes for TurboSHAKE128) with no forced
permutation boundaries. The sponge permutation occurs only when the rate buffer fills naturally. For a typical AEAD
header — `Init` + `Mix(key)` + `Mix(nonce)` + `Mix(ad)` with a 32-byte key, 12-byte nonce, and 16-byte AD — the total
frame size is approximately 80 bytes, fitting within a single rate block with zero permutation calls before encryption
begins.

### 12.3 Constant-Time Operation

Implementations MUST ensure constant-time processing for all secret data. Tag verification in `Open` MUST use
constant-time comparison. TreeWrap key derivation and encryption MUST not branch on secret values.

### 12.4 Memory Sanitization

**Plaintext on failed `Open`.** `Open` decrypts ciphertext before verifying the tag. If verification fails, the
plaintext buffer contains unauthenticated data that MUST be zeroed before returning. Implementations that decrypt
in-place MUST overwrite the buffer with zeros (not with the original ciphertext, which may itself be
attacker-controlled). Callers MUST NOT read or act on plaintext from a failed `Open`.

**Protocol state.** The `Clear` operation (§10.9) zeros the sponge state, buffered key material, and stored `Init`
label. Implementations SHOULD also zero derived TreeWrap keys and intermediate chain values as soon as they are no
longer needed. For forward secrecy to hold after `Ratchet`, the pre-`Ratchet` sponge state MUST be erased; retaining it
in memory defeats the purpose of ratcheting.

**Language-level considerations.** In languages with garbage collection or compiler optimizations that may elide stores
to dead memory, implementations MUST use platform-specific secure-zeroing primitives (e.g., `explicit_bzero`,
`SecureZeroMemory`, `volatile` writes) to ensure that sensitive data is actually erased.

### 12.5 Practical Data Limits

The security bounds in §13.7 are expressed in terms of Keccak-p[1600,12] calls. This section converts
them to practical data volumes and provides operational recommendations.

**Sponge blocks per operation.** Each Keccak-p invocation processes one sponge block of $R = 168$ bytes.
The data complexity $\sigma$ counts the total number of Keccak-p invocations across all Thyrse backbone
and TreeWrap operations:

- A `Mix` operation absorbing $d$ bytes costs $\lceil(\text{frame overhead} + d) / 168\rceil$ blocks, but
  since non-finalizing operations pack into the running sponge state, the cost is amortized. A typical
  AEAD header (`Init` + `Mix(key)` + `Mix(nonce)` + `Mix(ad)` with a 32-byte key, 12-byte nonce, and
  16-byte AD) fits within a single rate block with zero permutation calls before encryption begins.

- A finalizing operation (`Derive`, `Ratchet`, `Mask`, `Seal`) forces at least 2 Keccak-p calls (one per
  TurboSHAKE128 evaluation for the chain value and output/key clones).

- TreeWrap encryption of $m$ bytes adds Keccak-p calls as specified in the TreeWrap specification. See
  the TreeWrap specification for per-invocation cost accounting.

**Data volume limits.** Setting a target of $\varepsilon_{\mathrm{indiff}} \leq 2^{-128}$ in the
indifferentiability bound $(\sigma + t)^2 / 2^{257}$ gives $\sigma + t \leq 2^{64.5}$. Assuming an
adversary offline budget of $t = 2^{64}$, the protocol's data budget is approximately $2^{64}$ sponge
blocks, or approximately $2^{71}$ bytes ($\approx 2.8$ exabytes). This limit is shared across all
operations in a single session (or globally in the multi-user setting).

**Per-session recommendations.** Although the global data limit is enormous, implementations should enforce
per-session limits as defense in depth:

- **Maximum message size per `Seal`/`Mask`:** No inherent limit beyond available memory, but
  implementations MAY enforce a limit of $2^{38}$ bytes (256 GB) per operation.

- **Maximum finalizations per session:** `Ratchet` at least every $2^{32}$ finalizations to limit the
  chain collision term and provide forward secrecy.

- **Session rekeying:** For sessions processing more than $2^{48}$ bytes cumulatively, rekey by
  establishing a new session with fresh key material.

## 13. Security Considerations

### 13.1 Assumptions

The security analysis relies on the following properties of Thyrse's underlying primitives. Each is
conditional on Keccak-p[1600,12] behaving as an ideal permutation at the claimed workloads.

**TurboSHAKE128.** Indifferentiable from a random oracle under the ideal permutation model for
Keccak-p[1600,12] (Bertoni, Daemen, Peeters, Van Assche, 2008). The indifferentiability advantage is
bounded by $(\sigma + t)^2 / 2^{c+1}$, where $\sigma$ is the total number of online Keccak-p calls, $t$
is the adversary's offline Keccak-p budget, and $c = 256$ is the capacity in bits. TurboSHAKE128
evaluations with distinct domain separation bytes are modeled as independent random oracles, justified by
the domain byte occupying a structurally distinct position in the sponge padding.

**KT128.** Collision resistance of $H$-byte (64-byte) digests: 256-bit collision resistance under the
Keccak sponge claim, exceeding the 128-bit security target.

**TreeWrap.** Under a uniformly random $C$-byte key, TreeWrap provides:

- **IND-CPA** confidentiality (nonce-free: each key is used once).
- **INT-CTXT** authenticity, with forgery probability at most $S / 2^{8C}$ for $S$ attempts.
- **CMT-4** committing security: a ciphertext does not admit two valid openings under one key.
- **Tag PRF:** the full $C$-byte tag is a pseudorandom function of (key, ciphertext).

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
| MixDigest   | Collision-resistant binding   | —                                                 |

Sections 13.4–13.6 establish these claims. Section 13.7 gives the concrete combined bound.

### 13.3 Domain Separation

All operation codes are in the range `0x10`–`0x18`. All TurboSHAKE128 domain bytes used by the Thyrse
backbone are in the range `0x20`–`0x24`. KT128 pre-hashing uses domain byte `0x07`. These three ranges
are pairwise disjoint.

Operation codes and domain bytes serve structurally distinct roles: operation codes appear in the
transcript encoding (the message to TurboSHAKE128), while domain bytes appear in the sponge padding (the
finalization parameter of TurboSHAKE128). No confusion between the two is possible regardless of byte
values.

The recoverable encoding (§11) ensures that distinct operation sequences produce distinct transcripts.
Combined with the domain byte separation above, each TurboSHAKE128 evaluation in the protocol receives a
unique (message, domain byte) pair, which maps to an independent random oracle output.

TreeWrap's internal domain bytes are specified in the TreeWrap specification and covered by its own domain
separation analysis. They do not appear in the Thyrse transcript and are not relevant to the Thyrse-level
security argument.

### 13.4 Per-Instance Security

Each transcript instance — from its initial `CHAIN` frame (or `INIT`, for Instance 0) through
finalization — is a single TurboSHAKE128 evaluation on a recoverably-encoded input. This matches the
RO-KDF construction of Backendal, Clermont, Fischlin, and Günther (Theorems 8 and 9 of ePrint 2025/657).

Under TurboSHAKE128's indifferentiability from a random oracle (§13.1), the RO-KDF proof gives: the
output of each finalization is indistinguishable from random as long as at least one input to the
transcript instance is unpredictable. In the notation of Backendal et al., the recoverable encoding
$\langle\cdot\rangle$ is the frame encoding defined in §§4–5 of this specification, and the source
collection corresponds to the key material, nonces, and chain values absorbed into the instance.

Two finalizations of the same transcript with different domain bytes (e.g., chain value with `0x20` and
derived output with `0x21`) produce independent outputs. This follows from modeling TurboSHAKE128 with
distinct domain bytes as independent random oracles (§13.1).

### 13.5 Composition Across Chain Boundaries

The RO-KDF proof (§13.4) covers a single TurboSHAKE128 evaluation. This section extends the argument
across chain boundaries, where one instance's chain value feeds into the next instance's transcript.

Consider Instance $k$, which finalizes with domain bytes `0x20` (chain) and some output domain byte $D$
(derive/key). Let $\mathit{cv}_k$ denote the chain value and $\mathit{out}_k$ denote the derived output
or key.

**Independence of chain value and output.** Since $\mathit{cv}_k$ and $\mathit{out}_k$ come from
independent random oracles on the same transcript (§13.4), they are independent. An adversary who observes
$\mathit{out}_k$ (or ciphertext encrypted under a key derived from $\mathit{out}_k$) gains no information
about $\mathit{cv}_k$.

**Chain value as unpredictable source.** Instance $k{+}1$ begins by absorbing the `CHAIN` frame
containing $\mathit{cv}_k$. In the random oracle model, $\mathit{cv}_k$ is uniformly random — it is the
output of an RO on a transcript that the adversary has not queried, because doing so would require
predicting the unpredictable inputs to Instance $k$. Therefore $\mathit{cv}_k$ satisfies the
unpredictability requirement of Theorem 8 in Backendal et al., and the RO-KDF proof applies to
Instance $k{+}1$.

**Tag absorption in `Mask`/`Seal` instances.** For `Mask` and `Seal` instances, the `CHAIN` frame also
absorbs the TreeWrap tag. The tag is a PRF of the TreeWrap key and the ciphertext (§13.1). Since the
TreeWrap key is derived from a different domain byte than the chain value (e.g., `0x22` or `0x23` vs.
`0x20`), the key and chain value are independent. Therefore the tag — being a deterministic function of
the independent key and the public ciphertext — reveals no information about $\mathit{cv}_k$. The
composition argument is preserved.

**Induction.** By induction, the security of Instance $k{+}1$ reduces to the security of Instance $k$
(via the pseudorandomness of $\mathit{cv}_k$), which ultimately reduces to the unpredictability of the
original key material in Instance 0.

**Chain value collisions.** Each chain value is $H = 64$ bytes (512 bits). The birthday bound for chain
value collisions across $q$ instances is $q^2 / 2^{8H+1} = q^2 / 2^{513}$. A collision would cause two
instances to share identical subsequent transcripts. For $q \leq 2^{48}$, this probability
is $2^{-417}$, far below the 128-bit security target.

### 13.6 Operation-Specific Arguments

**Derive.** Direct application of §13.4. The output is produced by TurboSHAKE128 with domain byte `0x21`
on the current transcript. Under the RO-KDF argument, this output is indistinguishable from random given
an unpredictable input in the transcript.

**Ratchet.** The chain value (domain byte `0x24`) is the sole output. The pre-ratchet transcript is
unrecoverable from the chain value by TurboSHAKE128 preimage resistance. Forward secrecy holds provided
the implementation erases the pre-ratchet sponge state from memory (§12.4). Without erasure, an adversary
who compromises the post-ratchet state and retains access to the pre-ratchet sponge state can recover
prior keys.

**Mask / Unmask.** The TreeWrap key is derived via TurboSHAKE128 with domain byte `0x22` on the current
transcript. Under the RO-KDF argument (§13.4), this key is indistinguishable from a uniformly random
$C$-byte string as long as the transcript contains an unpredictable input. By the TreeWrap IND-CPA
assumption (§13.1), `Mask` provides IND-CPA confidentiality.

The tag absorbed into the `CHAIN` frame is independent of the chain value, preserving composition
(§13.5). If the ciphertext is tampered with, the sender and receiver compute different tags, causing their
transcripts to diverge and all subsequent operations to produce different results. However, `Mask` alone
does not provide integrity guarantees. Applications requiring integrity should use `Seal` or authenticate
the ciphertext externally (e.g., via a signature over a subsequent `Derive` output).

**Seal / Open.** The TreeWrap key is derived via domain byte `0x23`. The same RO-KDF argument gives a key
indistinguishable from random. By the TreeWrap IND-CPA and INT-CTXT assumptions (§13.1), `Seal` provides
IND-CCA2 security via generic composition (Bellare and Namprempre, ASIACRYPT 2000): IND-CPA + INT-CTXT
implies IND-CCA2. CMT-4 committing security follows from TreeWrap's CMT-4 claim (§13.1).

`Open` advances the transcript unconditionally with the computed tag. On verification failure, the
receiver's computed tag differs from the sender's, and the `CHAIN` frame absorbs a different value. This
permanently desynchronizes the protocol state: all subsequent operations produce different results. After
a failed `Open`, the protocol instance MUST be discarded.

**Fork.** `Fork` does not finalize. All $N{+}1$ branches share identical transcript up to the fork point
and diverge via their ordinals and (for clones) branch-specific values. The ordinal alone ensures the base
is distinct from all clones. Since the encoding is injective (§11), distinct ordinals or values produce
distinct transcripts, guaranteeing independent outputs at any subsequent finalization. Callers MUST ensure
clone values are distinct from each other.

**MixDigest.** `MixDigest` absorbs a KT128 digest rather than the raw data. The $H = 64$ byte digest
provides 256-bit collision resistance (§13.1), exceeding the 128-bit security target. The `Init` label is
used as the KT128 customization string, ensuring that digests are protocol-specific: two different
protocols produce different digests for the same input data.

### 13.7 Concrete Security Bound

This section gives the combined security bound for the Thyrse framework. The reduction has three layers:
replace the sponge with a random oracle (indifferentiability), apply the RO-KDF argument per instance with
inductive composition (§§13.4–13.5), and invoke TreeWrap's security as a black box (§13.1).

**Parameters.**

| Symbol   | Meaning                                                                       |
|----------|-------------------------------------------------------------------------------|
| $q$      | Total number of finalizing operations across the protocol lifetime            |
| $\sigma$ | Total data complexity: number of Keccak-p[1600,12] calls made by the protocol |
| $t$      | Adversary's offline computation budget in Keccak-p[1600,12] calls             |
| $S$      | Number of forgery attempts against `Seal`/`Open`                              |
| $c$      | TurboSHAKE128 capacity = 256 bits                                             |
| $H$      | Chain value length = 512 bits                                                 |

The data complexity $\sigma$ counts all Keccak-p calls made by Thyrse backbone operations (TurboSHAKE128
finalizations, KT128 pre-hashing) and by TreeWrap encryption/decryption. Although TreeWrap's security is
analyzed separately, its Keccak-p calls share the same ideal permutation and therefore contribute to the
global indifferentiability budget.

**Combined bound.**

$$\varepsilon_{\mathrm{total}} \leq \varepsilon_{\mathrm{perm}} + \frac{(\sigma + t)^2}{2^{c+1}} + q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{q^2}{2^{8H+1}} + \varepsilon_{\mathrm{tw}}$$

where:

- $\varepsilon_{\mathrm{perm}}$ is the advantage of distinguishing Keccak-p[1600,12] from a random
  permutation (conjectured negligible).
- $(\sigma + t)^2 / 2^{c+1} = (\sigma + t)^2 / 2^{257}$ is the sponge indifferentiability term, covering
  all Keccak-p evaluations globally (Thyrse backbone and TreeWrap internals).
- $q \cdot \varepsilon_{\mathrm{kdf}}(0)$ is $q$ times the per-instance RO-KDF bound, which depends on
  the unpredictability of the caller's key material. For key material with $\kappa$ bits of min-entropy,
  $\varepsilon_{\mathrm{kdf}}(0) \leq 2 \cdot t / 2^{\kappa}$.
- $q^2 / 2^{8H+1} = q^2 / 2^{513}$ bounds chain value collisions (§13.5).
- $\varepsilon_{\mathrm{tw}}$ is TreeWrap's per-invocation security advantage, treated as a black-box
  term. See the TreeWrap specification (§6.11) for the concrete bound; the dominant term is
  $S / 2^{8C} = S / 2^{256}$ for forgery resistance.

**Numerical evaluation.** For typical parameters — $q \leq 2^{48}$ finalizations,
$\sigma + t \leq 2^{64}$ total Keccak-p calls, $S \leq 2^{48}$ forgery attempts, and 256-bit key
material ($\kappa = 256$):

- Indifferentiability: $(2^{64})^2 / 2^{257} = 2^{-129}$
- RO-KDF: $2^{48} \cdot 2 \cdot 2^{64} / 2^{256} = 2^{-143}$
- Chain collisions: $(2^{48})^2 / 2^{513} = 2^{-417}$
- TreeWrap forgery: $2^{48} / 2^{256} = 2^{-208}$

The indifferentiability term dominates. The 128-bit security target is met as long as the caller ensures
$\varepsilon_{\mathrm{kdf}}(0) \leq 2^{-128}$ (i.e., the original key material has at least 128 bits of
min-entropy) and the total data complexity satisfies $\sigma + t \leq 2^{64}$.

### 13.8 Multi-User Security

The bound in §13.7 covers a single protocol session. In a multi-user setting with $U$ independent sessions
(each with an independent key), the adversary's advantage increases because it can target any session.

**Multi-user indifferentiability.** The sponge indifferentiability term is a global resource shared across
all sessions. If the adversary makes $t$ offline Keccak-p queries and the $U$ sessions collectively
process $\sigma_{\mathrm{total}}$ Keccak-p calls, the indifferentiability term is:

$$\varepsilon_{\mathrm{indiff}} \leq \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}}$$

The adversary does not gain a per-user multiplier because indifferentiability is a global property of the
permutation.

**Multi-user key recovery.** The adversary can attempt to recover any of the $U$ session keys. Under the
RO-KDF argument, each session key is derived from a TurboSHAKE128 evaluation on a transcript containing
unpredictable key material. This gives a multi-target advantage of:

$$\varepsilon_{\mathrm{mu\text{-}key}} \leq U \cdot \varepsilon_{\mathrm{kdf}}(0)$$

For 256-bit key material and an adversary with budget $t = 2^{64}$ across $U = 2^{32}$ users:
$\varepsilon_{\mathrm{mu\text{-}key}} \approx 2^{32} \cdot 2^{64} / 2^{256} = 2^{-160}$.

**Multi-user chain collisions.** The probability of a cross-session chain collision is:

$$\varepsilon_{\mathrm{mu\text{-}chain}} \leq \frac{(U \cdot q)^2}{2^{513}}$$

For $U = 2^{32}$ sessions with $q = 2^{32}$ finalizations each:
$(2^{64})^2 / 2^{513} = 2^{-385}$.

**Multi-user forgery.** The total forgery advantage across all sessions is $S / 2^{256}$, where $S$ is the
total number of forgery attempts.

**Combined multi-user bound:**

$$\varepsilon_{\mathrm{mu\text{-}total}} \leq \varepsilon_{\mathrm{perm}} + \frac{(\sigma_{\mathrm{total}} + t)^2}{2^{257}} + U \cdot q \cdot \varepsilon_{\mathrm{kdf}}(0) + \frac{(U \cdot q)^2}{2^{513}} + \frac{S}{2^{256}}$$

**Ratcheting as mitigation.** After a `Ratchet` operation, the session state contains only a chain
value — a 512-bit pseudorandom string with no algebraic structure exploitable in a multi-target search.
An adversary targeting pre-ratchet key material must do so before the ratchet occurs. If a session
ratchets every $W$ finalizing operations, the adversary must target a specific epoch rather than the full
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
- RFC 9861: KangarooTwelve and TurboSHAKE.
- NIST SP 800-185: SHA-3 Derived Functions (`left_encode`, `right_encode`).
- TreeWrap128 specification. Defines the tree-parallel authenticated encryption scheme used by Mask and
  Seal. Provides IND-CPA, INT-CTXT, CMT-4, and tag PRF security claims referenced in §13.1.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sponge functions." ECRYPT Hash Workshop,
  2008. Establishes sponge indifferentiability from a random oracle.
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
| Derive output | `91a9244784060174970bbbe8395f7f7e4d055c16be368594c0707413dcdfcc58` |

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
| Derive output | `fcac8c24985876bdd4e034552fdbeedca786fb7689a196a3acaf643f1c1c2a6a` |

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
| Seal output (ct ‖ tag) | `645c4ee5330811bf8f8a2070651ea3c503c78d7ef8f2c03fce2f7f2493a95fd299c4743a56048c4b8beccf2eeb` |
| Derive output          | `3d0207b0f8e5238cadfb589172fffe8059827243b0b602c27f2cb2814031879b`                           |

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
| Mask output (ct)       | `260ea77cc6b8ee60b060cac87e6f`                                                                 |
| Seal plaintext         | `7365616c20746869732064617461`                                                                 |
| Seal output (ct ‖ tag) | `d3d859139486f7f39dd9228fac735abf9b1719ab161559cc834993b17296f801389aabdfcc52c659fcb2feeb48cb` |

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
| Derive (no Ratchet)    | `7533c628ab03a2be92718588568284f73f467a54f173d8aaa2035ae3d2672945` |
| Derive (after Ratchet) | `e1af44127866b8588c68e10f17ff7d1d37f12a4e3526a69d8cb220f241fefd31` |

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
| Base (ordinal 0)             | `b5b07c94401b4d6e6b9a9289c1ad858327822f7cbe1e459e8d58ccc5b5f40b5d` |
| Clone 1 / "prover" (ord 1)   | `ab999f91045ddeb4b743a03c9256b9fd7a913e1ebb3fcd28bed9680534292d63` |
| Clone 2 / "verifier" (ord 2) | `09236bba933c0d9937c93d2bc8ac77f65a87b380a88ad34ffec206e76892c0eb` |

### 16.7 MixDigest

Pre-hash of a 10 000-byte input via KT128.

```
Init("test.vector")
Mix("key", "test-key-material")
MixDigest("stream-data", <10000 bytes where byte[i] = i mod 251>)
Derive("output", 32)
```

| Field         | Value                                                              |
|---------------|--------------------------------------------------------------------|
| Derive output | `7e7a81e3d8c4dd701883430697e1aa956b0ad990a1b0823bc3eaca1f9078d768` |

### 16.8 Seal + Open Round-Trip

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
| Seal output (ct ‖ tag)         | `667911010907507537fa5ab3a8345d769cbc1167e26edaaa4a38f38a6430f09be3b7917b1ec1f30d667c811612` |
| Open plaintext                 | `68656c6c6f2c20776f726c6421`                                                                 |
| Derive("confirm") — both sides | `1cf32253d292ddb3c3b5ccca4c20daa63f45da40cc47b4598c9643b347035bb9`                           |

### 16.9 Seal + Open with Tampered Ciphertext

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
| Seal output                          | `179a9f4f36547f4ea60a196e670fc58051fc3cdd6ecc8f08a0a10256c7b443a402b852a75f1c38b1fffe3ec7f3` |
| Tampered (first byte XOR 0xff)       | `e89a9f4f36547f4ea60a196e670fc58051fc3cdd6ecc8f08a0a10256c7b443a402b852a75f1c38b1fffe3ec7f3` |
| Open result                          | ⊥ (authentication failed)                                                                    |
| Seal-side Derive("after")            | `658908d1d91755d5fb37ed7c6dce9d3710d34a5ec539510ab64b8a5b31ea0355`                           |
| Open-side Derive("after") [desynced] | `a978e9131f73341787f605755deeebd76e94999933717117bdb5f2aa56ac15e9`                           |

### 16.10 Multiple Seals in Sequence

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
| 1    | `6669727374206d657373616765`   | `d681dd5ad476651843c17f3cfbc54763223f105b8d47366467f7f73cbc4be367b26ad6a6ae04fc3bd49d14ee45`   |
| 2    | `7365636f6e64206d657373616765` | `2299b98eb976cf08820419f18f29f50fbf47cca91aa263faed9b18f7780a65166b19a9753b6ffc9c5bb93de6b736` |
| 3    | `7468697264206d657373616765`   | `a20c4d8f8eb687a8da1eeb5d6ddb8ca054c6d022bc0d0d4cbe97928e2928beaede3810f480c413abff9255d69f`   |
