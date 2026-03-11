# Thyrse: A Transcript-Based Cryptographic Protocol Framework

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Version</th><td>0.6</td></tr>
  <tr><th>Date</th><td>2026-03-09</td></tr>
  <tr><th>Security Target</th><td>128-bit</td></tr>
</table>

## 1. Introduction

Thyrse is a protocol framework that sequences cryptographic operations as frames appended to a transcript. At each
finalizing operation, KT128 (KangarooTwelve) is evaluated over the transcript to derive two independent outputs: a
**chain value** that seeds the next transcript instance, and an **operational output** (a key, pseudorandom bytes, or
both). Bulk encryption is delegated to TW128 when authenticated or unauthenticated ciphertext is needed.

This structure forms a **KDF chain**: each finalization consumes the current transcript and produces a chain value that
carries unpredictability forward into the next instance. If an adversary does not know any single input to a transcript
instance, they learn nothing about the chain value or operational output, and therefore nothing about any subsequent
link in the chain. Unpredictability propagates forward indefinitely through finalizations. This is the framework's
central security guarantee.

The framework provides the following operations:

- **`Init`**: Establish a protocol identity.
- **`Mix`**: Absorb key material, nonces, or associated data. Data may be streamed without knowing its length in
  advance.
- **`Derive`**: Produce pseudorandom output that is a function of the full transcript.
- **`Ratchet`**: Irreversibly advance the protocol state for forward secrecy.
- **`Mask`** / **`Unmask`**: Encrypt or decrypt without authentication. The caller is responsible for authenticating the
  ciphertext through external mechanisms.
- **`Seal`** / **`Open`**: Encrypt or decrypt with authentication. A failed `Open` causes the protocol state to
  diverge from the sender's.
- **`Fork`**: Clone the protocol state into independent branches with distinct identities.

## 2. Parameters

| Symbol | Value | Description                          |
|--------|-------|--------------------------------------|
| C      | 32    | TW128 key and tag size (bytes)    |
| H      | 64    | Chain value size (bytes)             |

## 3. Dependencies

**`KT128(M, S, ℓ)`:** KangarooTwelve as specified in RFC 9861. Takes a message `M`, a customization string `S`, and
an output length `ℓ` in bytes.

**`TW128.EncryptAndMAC(key, plaintext) → (ciphertext, tag)`:** As specified in the TW128 specification. Takes a
`C`-byte key and arbitrary-length plaintext; returns same-length ciphertext and a `C`-byte tag.

**`TW128.DecryptAndMAC(key, ciphertext) → (plaintext, tag)`:** Takes a `C`-byte key and arbitrary-length ciphertext;
returns same-length plaintext and a `C`-byte tag. TW128 does not perform tag verification; the caller is responsible
for comparing the returned tag against an expected value.

### 3.1 Integer and String Encoding

All integer and string encodings use primitives from NIST SP 800-185.

**`left_encode(x)`** encodes a non-negative integer `x` as a byte string consisting of the length of the encoding (in
bytes) followed by the big-endian encoding of `x`. It is self-delimiting when parsed left-to-right. For example:

- `left_encode(0)` = `0x01 0x00`
- `left_encode(127)` = `0x01 0x7F`
- `left_encode(256)` = `0x02 0x01 0x00`

**`right_encode(x)`** encodes a non-negative integer `x` as a byte string consisting of the big-endian encoding of `x`
followed by the length of the encoding (in bytes). `right_encode` is injective and suffix-free: the final byte
determines the encoding's length, so a `right_encode` value can be unambiguously parsed from the right end of any byte
string it terminates. For example:

- `right_encode(0)` = `0x00 0x01`
- `right_encode(127)` = `0x7F 0x01`
- `right_encode(256)` = `0x01 0x00 0x02`

**`encode_string(x)`** = `left_encode(len(x) × 8) ‖ x`

This is NIST SP 800-185's `encode_string`: the `left_encode` prefix encodes the bit-length of `x`, making the encoding
self-delimiting when parsed left-to-right.

## 4. Transcript Encoding

Throughout this section, $`|x|`$ denotes the length of byte string $`x`$ in bytes.

### 4.1 Frame Format

Each operation is encoded as a **frame**, a byte string of the form:

$`\mathrm{encode\_frame}(\mathit{op}, \mathit{label}, \mathit{value}) = \mathit{op} \mathbin\| \mathrm{encode\_string}(\mathit{label}) \mathbin\| \mathit{value}`$

where $`\mathit{op}`$ is a single byte identifying the operation (§5), $`\mathit{label}`$ is a byte string for domain
separation, and $`\mathit{value}`$ is a byte string of arbitrary length. Every frame begins with an $`\mathit{op}`$
byte, so $`|\mathrm{encode\_frame}(\ldots)| \geq 1`$.

This encoding is injective: distinct $`(\mathit{op}, \mathit{label}, \mathit{value})`$ triples produce distinct frame
byte strings, because $`\mathit{op}`$ is a fixed single byte and $`\mathrm{encode\_string}(\mathit{label})`$ is
self-delimiting, uniquely determining where $`\mathit{label}`$ ends and $`\mathit{value}`$ begins.

### 4.2 Transcript Encoding

A **transcript** is a sequence of inputs $`x_0, x_1, \ldots, x_{m-1}`$, each encoded as a frame
$`F_i = \mathrm{encode\_frame}(x_i)`$. The empty sequence ($`m = 0`$) is valid and encodes to the empty string.

Naively concatenating frames would not be injective: since frames have variable length, a concatenation could be split
at different boundaries to yield different frame sequences. The transcript encoding solves this by interleaving
**position markers** that record each frame's starting offset, making the concatenation injective.

```math
\mathrm{interleave}(F_0, \ldots, F_{m-1}) = F_0 \mathbin\| \mathrm{right\_encode}(s_0) \mathbin\| F_1 \mathbin\| \mathrm{right\_encode}(s_1) \mathbin\| \cdots \mathbin\| F_{m-1} \mathbin\| \mathrm{right\_encode}(s_{m-1})
```

where $`s_i`$ is the byte offset in the encoded transcript at which $`F_i`$ begins. The offsets are deterministic:
$`s_0 = 0`$, and for $`i > 0`$:

```math
s_i = s_{i-1} + |F_{i-1}| + |\mathrm{right\_encode}(s_{i-1})|
```

The full encoding is the composition:

```math
\mathrm{encode\_transcript}(x_0, \ldots, x_{m-1}) = \mathrm{interleave}(\mathrm{encode\_frame}(x_0), \ldots, \mathrm{encode\_frame}(x_{m-1}))
```

The encoding is injective at every level: distinct $`(\mathit{op}, \mathit{label}, \mathit{value})`$ triples produce
distinct frames (§4.1), and the position markers ensure distinct frame sequences produce distinct encoded transcripts.
This means distinct operation sequences always produce distinct inputs to KT128, which is essential for the KDF security
argument (§8). Note that the injectivity of the full encoding depends on each operation encoding its inputs into the
$`\mathit{value}`$ field injectively. The operations (§7) define their value encodings with this requirement in mind.

**Overhead.** Each frame incurs a position marker of $`|\mathrm{right\_encode}(s_i)|`$ bytes. For transcripts shorter
than 256 bytes, each marker is 2 bytes. For transcripts shorter than 65536 bytes, each marker is 3 bytes.

### 4.3 Streaming Construction

The encoding can be constructed incrementally:

1. Record the current transcript length as $`s_i`$.
2. Append the frame bytes (which may be streamed without knowing their length in advance).
3. When the frame is complete, append $`\mathrm{right\_encode}(s_i)`$.

No buffering or lookahead is required.

### 4.4 Chain Frame

Finalizing operations (§7) evaluate KT128 over the current transcript and then replace it with a single **chain frame**
that carries the derived values into the next transcript instance. The chain frame has the form:

$`(\texttt{0x08},\; \texttt{""},\; \mathit{origin\_op} \mathbin\| \mathrm{left\_encode}(n) \mathbin\| \mathrm{encode\_string}(v_1) \mathbin\| \cdots \mathbin\| \mathrm{encode\_string}(v_n))`$

where $`\mathit{origin\_op}`$ is the operation code of the finalizing operation and $`v_1, \ldots, v_n`$ are the derived
values (1 for Derive/Ratchet, 2 for Mask/Seal). The chain frame is interleaved with a position marker at offset 0,
forming a complete single-frame transcript.

## 5. Protocol Constants

### 5.1 Operation Codes

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

### 5.2 Customization Strings

Each KT128 evaluation uses a 1-byte customization string that identifies the purpose of the output:

| Byte | Purpose                        | Used by             |
|------|--------------------------------|---------------------|
| 0x20 | Chain value derivation (non-Ratchet) | Derive, Mask, Seal  |
| 0x21 | Derive output                  | Derive              |
| 0x22 | Mask key derivation            | Mask / Unmask       |
| 0x23 | Seal key derivation            | Seal / Open         |
| 0x24 | Ratchet chain derivation       | Ratchet             |

TW128's internal domain bytes are not listed here; they are specified in the TW128 specification
and covered by its own security analysis.

<!-- begin:code:ref/thyrse.py:constants -->
```python
C = 32   # TW128 key and tag size (bytes).
H = 64   # Chain value size (bytes).

# Operation codes.
OP_INIT    = 0x01
OP_MIX     = 0x02
OP_FORK    = 0x03
OP_DERIVE  = 0x04
OP_RATCHET = 0x05
OP_MASK    = 0x06
OP_SEAL    = 0x07
OP_CHAIN   = 0x08

# KT128 customization strings.
CS_CHAIN       = 0x20
CS_DERIVE      = 0x21
CS_MASK_KEY    = 0x22
CS_SEAL_KEY    = 0x23
CS_RATCHET     = 0x24


def _encode_frame(start: int, op: int, label: bytes, value: bytes = b"") -> bytes:
    """Encode a TKDF frame: op ‖ encode_string(label) ‖ value ‖ right_encode(start).

    Each frame records its own start position via right_encode, making the
    transcript recoverable (§5).
    """
    return bytes([op]) + encode_string(label) + value + right_encode(start)


def _encode_chain(origin_op: int, *values: bytes) -> bytearray:
    """Encode a CHAIN frame that replaces the transcript after a finalizing operation.

    Finalizing operations (Derive, Ratchet, Mask, Seal) evaluate KT128 over
    the current transcript, then replace it with a single CHAIN frame.  The
    frame carries the origin operation code and all derived values so the
    transcript records which operation produced the chain and what was fed
    back into it.
    """
    payload = bytes([origin_op]) + left_encode(len(values))
    for v in values:
        payload += encode_string(v)
    return bytearray(_encode_frame(0, OP_CHAIN, b"", payload))
```
<!-- end:code:ref/thyrse.py:constants -->

## 6. Protocol State

The protocol state is a byte string called the **transcript**, initially empty. Operations append frames to the
transcript (§4). Finalizing operations evaluate KT128 over the transcript and then reset it to a single chain
frame (§4.4).

**Transcript invariants.** By construction, a valid transcript always begins with either an `INIT` frame (`0x01`) for the
first instance or a `CHAIN` frame (`0x08`) for subsequent instances after finalization. The first operation on a new
protocol instance MUST be `Init`, and `Init` MUST NOT be called more than once on the same instance. A `CHAIN` origin
byte is always one of `0x04`, `0x05`, `0x06`, `0x07` (the finalizing operation codes). These invariants hold by
construction when the operations are used as specified; implementations do not need to validate transcript structure at
runtime.

**Determinism.** Thyrse is deterministic: identical transcripts produce identical outputs. There is no internal nonce or
randomness. Confidentiality requires that callers absorb fresh, unpredictable values via `Mix` before any encrypting
operation (`Mask` or `Seal`). Replaying the same operation sequence with the same inputs produces identical ciphertext.

<!-- begin:code:ref/thyrse.py:protocol_core -->
```python
class Protocol:
    def __init__(self):
        self.transcript = bytearray()
```
<!-- end:code:ref/thyrse.py:protocol_core -->

## 7. Operations

All operations append frames as $`(\mathit{op}, \mathit{label}, \mathit{value})`$ triples, encoded per §4.1 and
interleaved with position markers per §4.2. $`T`$ denotes the encoded transcript.

### 7.1 Init

Establishes the protocol identity. The `Init` label provides protocol-level domain separation: two protocols using
different `Init` labels produce cryptographically independent transcripts even if all subsequent operations are
identical. See §6 for transcript validity requirements.

**`Init(label)`**

Append frame `(0x01, label, "")`.

<!-- begin:code:ref/thyrse.py:init -->
```python
    def init(self, label: bytes):
        self.transcript += _encode_frame(len(self.transcript), OP_INIT, label)
```
<!-- end:code:ref/thyrse.py:init -->

### 7.2 Mix

Absorbs data into the protocol transcript. `Mix` is used for both secret inputs (key material, ephemeral keys) and
public inputs (nonces, associated data, protocol messages). Data may be streamed without knowing its length in advance;
the position marker closes the frame when the operation completes.

**`Mix(label, data)`**

Append frame `(0x02, label, data)`.

<!-- begin:code:ref/thyrse.py:mix -->
```python
    def mix(self, label: bytes, data: bytes):
        self.transcript += _encode_frame(len(self.transcript), OP_MIX, label, data)
```
<!-- end:code:ref/thyrse.py:mix -->

### 7.3 Fork

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

<!-- begin:code:ref/thyrse.py:fork -->
```python
    def fork(self, label: bytes, *values: bytes) -> list["Protocol"]:
        N = len(values)
        snapshot = bytes(self.transcript)
        self.transcript += _encode_frame(len(self.transcript), OP_FORK, label,
            left_encode(N) + left_encode(0) + encode_string(b""))
        clones = []
        for i, val in enumerate(values, start=1):
            clone = Protocol()
            clone.transcript = bytearray(snapshot)
            clone.transcript += _encode_frame(len(clone.transcript), OP_FORK,
                label, left_encode(N) + left_encode(i) + encode_string(val))
            clones.append(clone)
        return clones
```
<!-- end:code:ref/thyrse.py:fork -->

### 7.4 Derive

Produces pseudorandom output that is a deterministic function of the full transcript. Finalizes the current transcript
and begins a new one.

Derive output is collision-resistant and preimage-resistant. When the transcript contains at least one unpredictable
input, the output is additionally pseudorandom (§8.5).

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

<!-- begin:code:ref/thyrse.py:derive -->
```python
    def derive(self, label: bytes, output_len: int) -> bytes:
        assert output_len > 0
        self.transcript += _encode_frame(
            len(self.transcript), OP_DERIVE, label, left_encode(output_len))
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        output = kt128(T, bytes([CS_DERIVE]), output_len)
        self.transcript = _encode_chain(OP_DERIVE, chain)
        return output
```
<!-- end:code:ref/thyrse.py:derive -->

### 7.5 Ratchet

Irreversibly advances the protocol state. No user-visible output is produced.

Ratchet provides forward secrecy: an adversary who compromises the post-ratchet state cannot recover the pre-ratchet
state, provided the implementation securely erases pre-finalization state (§8.8).

**`Ratchet(label)`**

1. Append frame `(0x05, label, "")`.

2. Derive a chain value:

- `chain_value ← KT128(T, 0x24, H)`

3. Reset the transcript to a single frame:

- `(0x08, "", 0x05 ‖ left_encode(1) ‖ encode_string(chain_value))`

<!-- begin:code:ref/thyrse.py:ratchet -->
```python
    def ratchet(self, label: bytes):
        self.transcript += _encode_frame(
            len(self.transcript), OP_RATCHET, label)
        T = bytes(self.transcript)
        ratchet_value = kt128(T, bytes([CS_RATCHET]), H)
        self.transcript = _encode_chain(OP_RATCHET, ratchet_value)
```
<!-- end:code:ref/thyrse.py:ratchet -->

### 7.6 Mask / Unmask

Encrypts (`Mask`) or decrypts (`Unmask`) without authentication. Use `Mask` when integrity is provided by an external
mechanism (e.g., a signature over the transcript) or when confidentiality alone is sufficient.

Callers MUST ensure that a fresh, unpredictable value (such as a nonce or ephemeral key) has been absorbed via `Mix`
before any `Mask` operation. If two protocol runs reach the same transcript state and then `Mask` different plaintexts,
they derive the same TW128 key. This is catastrophic: TW128 with a repeated key leaks plaintext XOR differences,
fully compromising confidentiality. This requirement is analogous to the nonce requirement of conventional AEAD schemes;
it is the caller's responsibility and is not enforced by the framework.

When the transcript contains at least one unpredictable input, Mask provides IND-CPA confidentiality (§8.6).

**`Mask(label, plaintext) → ciphertext`**

1. Append frame `(0x06, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x22, C)`

3. Encrypt:

- `(ciphertext, tag) ← TW128.EncryptAndMAC(key, plaintext)`

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

- `(plaintext, tag) ← TW128.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript to a single frame:

- `(0x08, "", 0x06 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(tag))`

Return `plaintext`.

*Warning:* Any application-level processing of the unmasked plaintext MUST be treated as untrusted and safely buffered
until an external authenticating operation (such as verifying a signature over a subsequent `Derive` output) has
succeeded.

Because `Mask` provides no authentication, a tampered ciphertext produces a different tag at the receiver, causing the
sender's and receiver's transcripts to silently diverge. All subsequent outputs will differ. Unlike a failed `Open`,
there is no error signal — the divergence is detectable only through a later authentication check.

<!-- begin:code:ref/thyrse.py:mask_unmask -->
```python
    def mask(self, label: bytes, plaintext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_MASK, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        mask_key = kt128(T, bytes([CS_MASK_KEY]), C)
        ct, tag = encrypt_and_mac(mask_key, plaintext)
        self.transcript = _encode_chain(OP_MASK, chain, tag)
        return ct

    def unmask(self, label: bytes, ciphertext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_MASK, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        mask_key = kt128(T, bytes([CS_MASK_KEY]), C)
        pt, tag = decrypt_and_mac(mask_key, ciphertext)
        self.transcript = _encode_chain(OP_MASK, chain, tag)
        return pt
```
<!-- end:code:ref/thyrse.py:mask_unmask -->

### 7.7 Seal / Open

Encrypts (`Seal`) or decrypts (`Open`) with authentication. Use `Seal` when the ciphertext must be verified on receipt.
A failed `Open` causes the receiver's protocol state to diverge from the sender's, because the CHAIN frame absorbs
the receiver's computed tag rather than the sender's.

Callers MUST ensure that a fresh, unpredictable value has been absorbed via `Mix` before any `Seal` operation. The same
catastrophic key reuse applies as for `Mask` (§7.6).

When the transcript contains at least one unpredictable input, Seal provides IND-CPA confidentiality, INT-CTXT
authenticity, and CMT-4 committing security (§8.6).

**`Seal(label, plaintext) → ciphertext ‖ tag`**

1. Append frame `(0x07, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x23, C)`

3. Encrypt:

- `(ciphertext, tag) ← TW128.EncryptAndMAC(key, plaintext)`

4. Reset the transcript to a single frame:

- `(0x08, "", 0x07 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(tag))`

The two KT128 evaluations are independent and may execute in parallel.

Return `ciphertext ‖ tag`. The ciphertext has the same length as the plaintext; the tag occupies the final $`C`$ bytes
of the returned value.

**`Open(label, ciphertext, tag) → plaintext or ⊥`**

The `tag` parameter MUST be exactly $`C`$ bytes. The `ciphertext` has the same length as the original plaintext.

1. Append frame (identical to `Seal`): `(0x07, label, "")`.

2. Evaluate KT128 twice:

- `chain_value ← KT128(T, 0x20, H)`
- `key ← KT128(T, 0x23, C)`

3. Decrypt:

- `(plaintext, computed_tag) ← TW128.DecryptAndMAC(key, ciphertext)`

4. Reset the transcript (unconditionally) to a single frame:

- `(0x08, "", 0x07 ‖ left_encode(2) ‖ encode_string(chain_value) ‖ encode_string(computed_tag))`

5. Verify:

- If `computed_tag ≠ tag` (constant-time comparison), discard `plaintext` and return ⊥. The protocol state has
  diverged from the sender's because the CHAIN frame absorbed `computed_tag`, not the sender's `tag`. All subsequent
  outputs will differ from the sender's.

Return `plaintext`.

<!-- begin:code:ref/thyrse.py:seal_open -->
```python
    def seal(self, label: bytes, plaintext: bytes) -> bytes:
        self.transcript += _encode_frame(
            len(self.transcript), OP_SEAL, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        seal_key = kt128(T, bytes([CS_SEAL_KEY]), C)
        ct, tag = encrypt_and_mac(seal_key, plaintext)
        self.transcript = _encode_chain(OP_SEAL, chain, tag)
        return ct + tag

    def open(self, label: bytes, ciphertext: bytes, tag: bytes) -> bytes | None:
        self.transcript += _encode_frame(
            len(self.transcript), OP_SEAL, label)
        T = bytes(self.transcript)
        chain = kt128(T, bytes([CS_CHAIN]), H)
        seal_key = kt128(T, bytes([CS_SEAL_KEY]), C)
        pt, computed_tag = decrypt_and_mac(seal_key, ciphertext)
        self.transcript = _encode_chain(OP_SEAL, chain, computed_tag)
        if not hmac.compare_digest(computed_tag, tag):
            return None
        return pt
```
<!-- end:code:ref/thyrse.py:seal_open -->

### 7.8 Utility Operations

**`Clone() → copy`**

Returns an independent copy of the protocol state (transcript and, in sponge-based implementations, the full sponge
state and `Init` label). The original and clone evolve independently. `Clone` does not append a frame to the transcript.

*Warning:* Because `Clone` does not append a frame, applying identical operations to the original and the clone will
produce identical transcripts, leading to catastrophic key reuse in `Mask` or `Seal`. Callers MUST use `Fork` to create
independent protocol branches unless they are explicitly managing transcript divergence (e.g., transferring state from
sender to receiver where the two sides perform different operations).

**`Clear()`**

Overwrites the protocol state with zeros and invalidates the instance. After `Clear`, the instance MUST NOT be used.

<!-- begin:code:ref/thyrse.py:clone_clear -->
```python
    def clone(self) -> "Protocol":
        copy = Protocol()
        copy.transcript = bytearray(self.transcript)
        return copy

    def clear(self):
        for i in range(len(self.transcript)):
            self.transcript[i] = 0
        self.transcript = bytearray()
```
<!-- end:code:ref/thyrse.py:clone_clear -->

## 8. Security Argument

The security argument proceeds in five steps: (1) the transcript encoding is recoverable (§8.2); (2) each finalization
is KDF-secure and collision-resistant (§8.3); (3) the chain value and operational output are independent (§8.4);
(4) unpredictability propagates through the KDF chain (§8.5); (5) each operation inherits concrete security properties
from the chain (§8.6).

### 8.1 Assumptions

The security analysis relies on the following properties of Thyrse's underlying primitives, each conditional on
Keccak-p[1600,12] behaving as an ideal permutation.

**KT128.** KT128 is built on TurboSHAKE128 using Sakura encoding for tree hashing. TurboSHAKE128 is indifferentiable from a random oracle under the ideal permutation model for Keccak-p[1600,12] (Bertoni, Daemen, Peeters, Van Assche, 2008) with advantage $`(\sigma + t)^2 / 2^{c+1}`$, where $`c = 256`$ is the capacity, $`\sigma`$ is the total number of online Keccak-p calls, and $`t`$ is the adversary's offline budget. By the indifferentiability composition theorem (Maurer, Renner, Holenstein, 2004), the combined indifferentiability advantage of KT128 from a random oracle is at most:

```math
\varepsilon_{\mathrm{indiff}} \leq \frac{q_{\mathrm{tree}}^2}{2^{n+1}} + \frac{(\sigma + t)^2}{2^{c+1}}
```

where $`q_{\mathrm{tree}}`$ is the number of inner-function calls and $`n`$ is the chaining value bit-length
(Bertoni et al., "Sakura," 2014). For KT128, $`n = c = 256`$. Since $`q_{\mathrm{tree}} \leq \sigma`$ (tree-level calls are a subset of online Keccak-p calls), this simplifies
to $`\varepsilon_{\mathrm{indiff}} \leq 2(\sigma + t)^2 / 2^{c+1}`$. With $`c = 256`$, the 128-bit security level is
maintained.

**KT128 collision resistance.** Collision resistance of $`H`$-byte (64-byte) digests: 256-bit collision resistance under
the Keccak sponge claim, exceeding the 128-bit security target.

**KT128 domain separation.** KT128 accepts a customization string $`S`$ whose encoding is injective (RFC 9861, §3.2).
Evaluations with distinct $`S`$ values therefore have disjoint input spaces and are modeled as independent random oracles.

**TW128.** Under a uniformly random $`C`$-byte key, TW128 provides:

- **IND-CPA** confidentiality (nonce-free: each key is used once).
- **INT-CTXT** authenticity, with forgery probability at most $`S / 2^{8C}`$ for $`S`$ attempts.
- **CMT-4** committing security (Bellare and Hoang, EUROCRYPT 2022): a ciphertext does not admit two valid openings under distinct $`(\mathit{key}, \mathit{plaintext})`$ pairs.
- **Tag PRF:** the full $`C`$-byte tag is a pseudorandom function of $`(\mathit{key}, \mathit{ciphertext})`$.

TW128 does not perform tag verification; the caller (Thyrse) is responsible. See the TW128 specification for proofs
of these properties.

### 8.2 KDF Security and the RO-KDF Construction

**KDF security.** A key derivation function is secure if its output is computationally indistinguishable from a
uniformly random string of the same length. The adversary may observe the context surrounding the derivation (public
parameters, protocol messages, labels) but cannot predict the output without knowing the secret key material.

**Multi-input KDF security.** Backendal, Clermont, Fischlin, and Günther (BCFG25) extend this to multi-input KDFs
($`n`$-KDFs), where the derivation combines $`n`$ key material inputs $`\sigma_i`$, each with associated context
$`c_i`$, a label $`L`$, and an output length $`\ell`$:

```math
K \leftarrow n\text{-}\mathrm{KDF}((\sigma_1, c_1), \ldots, (\sigma_n, c_n), L, \ell)
```

The key material inputs are drawn from a source collection $`\mathbf{\Sigma} = (\Sigma_1, \ldots, \Sigma_r)`$ with a
mapping $`\Sigma`$-map$`\colon [n] \to [r]`$ that assigns each input position to a source. BCFG25 Definition 6 defines
KDF security via a real-or-random game: the adversary can request derivations using honest keys (drawn from sources) and
adversarially chosen keys, and must distinguish real outputs from random. The $`n`$-KDF is secure if the output is
indistinguishable from random as long as at least one input in each derivation comes from an unpredictable source.

**The RO-KDF construction.** BCFG25 (§5.1) gives a generic construction for a secure $`n`$-KDF from any random oracle
$`\mathrm{H_T}`$ and a recoverable encoding $`\langle \cdot \rangle`$ of the inputs:

```math
\mathrm{RO\text{-}KDF}_n[\mathrm{H_T}]((\sigma_1, c_1), \ldots, (\sigma_n, c_n), L, \ell) = \mathrm{H_T}(\langle \sigma_1, c_1, \sigma_2, c_2, \ldots, \sigma_n, c_n, L \rangle)[1\,..\,\ell]
```

Following BCFG25, we require the encoding $`\langle \cdot \rangle`$ to be **recoverable**: (1) injective, so distinct input
tuples produce distinct encoded strings, and (2) efficiently decodable, so there exists a deterministic polynomial-time
algorithm that recovers the inputs from any encoded string and terminates on all inputs. Recoverability is what allows
the simulator in the security proof to inspect arbitrary random oracle queries and determine whether they contain a
target secret.

**Theorem 8 (BCFG25).** Let $`\mathrm{H_T}`$ be a random oracle (with fixed output length for NOF, or unbounded output
length for XOF). Let $`\mathbf{\Sigma} = (\Sigma_1, \ldots, \Sigma_r)`$ be a source collection with mapping
$`\Sigma`$-map, each source outputting at most $`u`$ elements. Let $`\mathit{req}`$ be $`\mathit{req}_N`$ (at least one
honest key per query) for NOF or $`\mathit{req}_X`$ (adding XOF freshness) for XOF. Then for any adversary $`\mathcal{A}`$ against the KDF security of
$`\mathrm{RO\text{-}KDF}_n[\mathrm{H_T}]`$:

```math
\mathrm{Adv}^{\mathrm{kdf}}_{\mathrm{RO\text{-}KDF}_n[\mathrm{H_T}], \mathbf{\Sigma}, \mathit{req}}(\mathcal{A}) \leq 2 \cdot \sum_{i=1}^{r} \mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}(\mathcal{B}_i)
```

for adversaries $`\mathcal{B}_i`$ with roughly the same running time as $`\mathcal{A}`$. Here
$`\mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}(\mathcal{B}_i)`$ is the **source-unpredictability advantage**: the maximum
probability that $`\mathcal{B}_i`$, given a prediction oracle, correctly guesses the output of source $`\Sigma_i`$.
The factor of 2 arises from
Proposition 7 of BCFG25, which shows that real KDF queries can be simulated via challenge oracle queries. The reduction
constructs a family of simulators $`\mathcal{B}_1, \ldots, \mathcal{B}_r`$, one per source. Each
$`\mathcal{B}_i`$ receives a sample from $`\Sigma_i`$ and simulates the KDF security game for $`\mathcal{A}`$. When
$`\mathcal{A}`$ makes a random oracle query, $`\mathcal{B}_i`$ uses the recoverable encoding's decoder to extract the
inputs and determine whether the query contains key material from $`\Sigma_i`$. If so, $`\mathcal{B}_i`$ calls its
prediction oracle. This is why recoverability is required: without an efficient decoder, $`\mathcal{B}_i`$ cannot
inspect adversarial queries.

**Thyrse as an RO-KDF.** Each Thyrse finalization is a direct instance of this construction.

First, KT128's domain separation (§8.1) establishes that each customization string selects an independent random oracle.
Each finalizing operation evaluates KT128 with a fixed customization string (e.g., `0x20` for chain values, `0x21` for
Derive output). These are independent RO-KDF instances, each with its own random oracle $`\mathrm{H_T}`$.

Second, within each oracle, the construction applies directly: the transcript encoding (§4) serves as the recoverable
encoding $`\langle \cdot \rangle`$, and each frame in the transcript — `Init`, `Mix`, `Fork`, `Chain`, or the finalizing
operation itself — corresponds to one input position of the $`n`$-KDF, with the frame's value field as the key material
$`\sigma_i`$ and the surrounding structure (operation code, label, position marker) as the context $`c_i`$. For `Mix`
frames carrying secret data, the source $`\Sigma_i`$ is the caller's key material distribution. For all other frames
(`Init` labels, `Fork` ordinals, `Chain` values from a previous finalization, the finalizing frame's own metadata), the
source produces values that are either public or determined by earlier protocol operations; these are modeled as
adversarially known inputs. Theorem 8's bound sums unpredictability advantages over all sources. Adversarially known
sources contribute zero to this sum, so the per-instance bound collapses to the unpredictability of the weakest secret
`Mix` source. Theorem 8 applies to each oracle independently.

Since each customization string selects an independent oracle, each oracle's freshness requirement can be considered
separately. The chain value (`0x20`), key derivation (`0x22`, `0x23`), and ratchet (`0x24`) oracles always produce
fixed-length output ($`H`$ or $`C`$ bytes), so they are NOF (non-XOF) uses requiring only $`\mathit{req}_N`$, which has
no freshness condition. Only the Derive output oracle (`0x21`) is a XOF use requiring $`\mathit{req}_X`$. The XOF
freshness condition is satisfied because `Derive` encodes $`\mathrm{left\_encode}(\mathit{output\_len})`$ in its frame
value (§7.4): two `Derive` calls with different output lengths produce different encoded inputs and therefore make
distinct random oracle queries.

It remains to show that the transcript encoding is recoverable.

### 8.3 Recoverability

This section proves that the Thyrse transcript encoding (§4) satisfies the recoverability requirement of the RO-KDF
construction (§8.2). The proof has three layers: the transcript can be parsed into frames, each frame can be parsed into
its inputs, and each operation's value encoding is itself injective. Together with Theorem 8 and KT128's collision
resistance (§8.1), this establishes that each Thyrse finalization is KDF-secure and collision-resistant.

#### 8.3.1 Transcript Recovery

The following algorithm recovers frame byte strings from an interleaved encoding by parsing position markers
right-to-left. All slice notation $`X[a \,..\, b]`$ denotes the half-open interval $`[a, b)`$.

**Deinterleave algorithm.** Given an encoded transcript $`T`$, set $`\mathrm{end} \leftarrow |T|`$. While
$`\mathrm{end} > 0`$: read the final byte of $`T[0 \,..\, \mathrm{end}]`$ as the length $`n`$ of the integer encoding
in $`\mathrm{right\_encode}(s_i)`$; decode the preceding $`n`$ bytes as $`s_i`$; verify that
$`s_i < \mathrm{end} - 1 - n`$ (the recovered offset is strictly less than the current position, ensuring monotonic
descent); extract $`T[s_i \,..\, \mathrm{end} - 1 - n]`$ as the frame byte string; set
$`\mathrm{end} \leftarrow s_i`$. Reverse the collected frames. If any step encounters insufficient bytes or the
monotonicity check fails, the input is malformed. The algorithm terminates in $`O(|T|)`$ time on all inputs: each
iteration reduces $`\mathrm{end}`$ by at least 3 bytes (one frame byte minimum, plus at least 2 bytes for
$`\mathrm{right\_encode}`$).

**Correctness (Claim 1).** For any non-empty frame byte strings $`F_0, \ldots, F_{m-1}`$ (i.e., $`|F_i| \geq 1`$,
as required by §4.1), $`\mathrm{deinterleave}(\mathrm{interleave}(F_0, \ldots, F_{m-1}))`$ returns
$`(F_0, \ldots, F_{m-1})`$.

*Proof.* **Base case ($`m = 0`$).** $`\mathrm{interleave}()`$ is the empty string. $`|T| = 0`$, the loop does not
execute, and the algorithm returns $`[]`$. Correct.

**Base case ($`m = 1`$).** $`T = F_0 \mathbin\| \mathrm{right\_encode}(0)`$. The algorithm reads
$`\mathrm{right\_encode}(0)`$ from the right, obtaining $`s_0 = 0`$. The frame bytes are
$`T[0 \,..\, \mathrm{end} - 1 - n] = F_0`$. It sets $`\mathrm{end} \leftarrow 0`$ and returns $`[F_0]`$. Correct.

**Inductive step.** Suppose the claim holds for all frame sequences of length $`k`$. Consider $`k + 1`$ frames. By
definition of `interleave`:

```math
T = \underbrace{F_0 \mathbin\| \mathrm{right\_encode}(s_0) \mathbin\| \cdots \mathbin\| F_{k-1} \mathbin\| \mathrm{right\_encode}(s_{k-1})}_{\mathrm{interleave}(F_0, \ldots, F_{k-1})} \mathbin\| F_k \mathbin\| \mathrm{right\_encode}(s_k)
```

The algorithm reads $`\mathrm{right\_encode}(s_k)`$ from the right, obtains $`s_k`$, and extracts $`F_k`$. It sets
$`\mathrm{end} \leftarrow s_k`$. By the recurrence (§4.2), $`T[0 \,..\, s_k]`$ is exactly
$`\mathrm{interleave}(F_0, \ldots, F_{k-1})`$. By the inductive hypothesis, the remaining iterations recover
$`F_0, \ldots, F_{k-1}`$. $`\square`$

#### 8.3.2 Frame Recovery

Each frame has the form $`\mathit{op} \mathbin\| \mathrm{encode\_string}(\mathit{label}) \mathbin\| \mathit{value}`$ (§4.1).
Given the frame byte string, the decoder reads the first byte as $`\mathit{op}`$, parses the
$`\mathrm{encode\_string}`$ prefix to extract $`\mathit{label}`$ (the $`\mathrm{left\_encode}`$ length header is
self-delimiting), and takes the remaining bytes as $`\mathit{value}`$. This is injective and runs in $`O(|F|)`$ time on
all inputs.

#### 8.3.3 Per-Operation Value Recovery

Within each frame, the $`\mathit{value}`$ field is a recoverable function of the operation's inputs:

- **`INIT` (`0x01`):** $`\mathit{value}`$ is empty.
- **`MIX` (`0x02`):** $`\mathit{value}`$ is the raw data.
- **`FORK` (`0x03`):** $`\mathit{value} = \mathrm{left\_encode}(N) \mathbin\| \mathrm{left\_encode}(\mathit{ordinal}) \mathbin\| \mathrm{encode\_string}(\mathit{branch\_value})`$.
- **`DERIVE` (`0x04`):** $`\mathit{value} = \mathrm{left\_encode}(\mathit{output\_len})`$.
- **`RATCHET` (`0x05`):** $`\mathit{value}`$ is empty.
- **`MASK` (`0x06`):** $`\mathit{value}`$ is empty.
- **`SEAL` (`0x07`):** $`\mathit{value}`$ is empty.
- **`CHAIN` (`0x08`):** $`\mathit{value} = \mathit{origin\_op} \mathbin\| \mathrm{left\_encode}(n) \mathbin\| \mathrm{encode\_string}(v_1) \mathbin\| \cdots \mathbin\| \mathrm{encode\_string}(v_n)`$.

Since $`\mathrm{left\_encode}`$ and $`\mathrm{encode\_string}`$ are self-delimiting, the $`\mathit{op}`$ byte selects the
value format, and each format is injective and recoverable.

#### 8.3.4 Composition

$`\mathrm{deinterleave}`$ is a left inverse of $`\mathrm{interleave}`$ (Claim 1). The frame decoder is a left inverse
of $`\mathrm{encode\_frame}`$. The per-operation value decoder is a left inverse of each operation's value encoding. Any
function with a left inverse is injective. By composition, the full transcript encoding is recoverable: injective, with a
polynomial-time decoder that recovers the complete input tuple from any encoded transcript.

By Theorem 8 (§8.2), each Thyrse finalization is therefore KDF-secure: the output is indistinguishable from random given
at least one unpredictable input in the transcript. Combined with KT128's collision resistance (§8.1), distinct
transcript instances produce distinct chain values except with negligible probability (quantified in §8.5), preventing subsequent transcripts
from converging. $`\square`$

### 8.4 Chain Independence

Each Thyrse finalization except `Ratchet` evaluates KT128 on the same transcript with two distinct customization
strings: one for the chain value (`0x20`) and one for the operational output (`0x21`–`0x23`, depending on the
operation). `Ratchet` evaluates only a single customization string (`0x24`) and produces no operational output. For the
non-ratchet operations, KT128's domain separation property (§8.1) means that distinct customization strings select
independent random oracles. The chain value and operational output are therefore independent: observing the operational
output (or ciphertext encrypted under a key derived from it) reveals no information about the chain value.

**Tag absorption.** For `Mask` and `Seal`, the chain frame absorbs the TW128 tag alongside the chain value. The tag
is a deterministic function of the TW128 key and the ciphertext, and the ciphertext is itself derived from the
TW128 key and the plaintext. Since the TW128 key is derived from a different customization string (`0x22` or
`0x23`) than the chain value (`0x20`), the key and chain value are independent. The entire tag computation is therefore
a function of quantities independent of the chain value, so absorbing the tag reveals no information about the chain
value and the composition argument is preserved.

### 8.5 KDF Chain Property

**Formal context.** Alwen, Coretti, and Dodis (ACD19) formalize a *KDF chain* as a PRF-PRNG primitive
(Definition 16): a pair $`(\mathsf{P\text{-}Init}, \mathsf{P\text{-}Up})`$ where $`\mathsf{P\text{-}Init}(k)`$ produces
an initial state $`\sigma`$ and $`\mathsf{P\text{-}Up}(\sigma, I)`$ produces a new state $`\sigma'`$ and an output
$`R`$. The PRF-PRNG security game (Definition 17, Figure 7) captures three properties in a single definition:
resilience (the output is pseudorandom when the state is refreshed with a uniformly random input), forward security
(corrupting the state does not compromise prior outputs), and the PRF property (adversarially chosen inputs on an
uncorrupted state produce pseudorandom outputs). This is the formal primitive underlying the symmetric-key ratchet in the Signal
protocol.

**Correspondence to Thyrse.** Each Thyrse finalization is an instance of $`\mathsf{P\text{-}Up}`$: the transcript plays
the role of the input $`I`$, the chain value (CS `0x20`) plays the role of the new state $`\sigma'`$, and
the operational output (CS `0x21`–`0x24`) plays the role of $`R`$. The chain independence
argument (§8.4) justifies treating $`\sigma'`$ and $`R`$ as independent, which is the analogue of the PRF-PRNG
security game's separation between PRNG mode (state refresh) and PRF mode (output derivation).

Thyrse's proof proceeds via BCFG25 (RO-KDF on a recoverable encoding) rather than ACD19's standard-model
PRF-PRNG reduction. ACD19's composition theorem targets bidirectional messaging (CKA + FS-AEAD + PRF-PRNG),
while Thyrse is a unidirectional transcript-based framework with a different operation set. The RO-KDF route gives
tighter bounds and follows directly from KT128's indifferentiability.

**KDF chain property.** Each finalization produces a chain value that is:

1. **Independent** of the operational output (§8.4).
2. **Unpredictable** to any adversary who does not know all inputs to the current transcript instance (§8.3, via
   Theorem 8).
3. **Absorbed as an input** to the next transcript instance, via the chain frame (§4.3).

By (2), the chain value is indistinguishable from a uniformly random $`H`$-byte string. By (3), it serves as an
unpredictable input to the next instance, satisfying the precondition of Theorem 8 for that instance. By (1), no
operational output from the current instance helps predict it.

**Hybrid argument.** Assume Instance 0 contains at least one unpredictable input, as required by the per-operation
preconditions (§7.4, §7.6, §7.7). The composition across $`q`$ instances is formalized as a sequence of $`q`$ hybrid
games. In Hybrid $`j`$ (for $`j = 0, \ldots, q`$), the chain values $`\mathit{cv}_0, \ldots, \mathit{cv}_{j-1}`$ are
replaced with
uniformly random strings independent of all other protocol values. Hybrid 0 is the real game; Hybrid $`q`$ replaces
all chain values with random. The transition from Hybrid $`j`$ to Hybrid $`j + 1`$ replaces $`\mathit{cv}_j`$ with a
random string. The reduction embeds the KDF security challenge at Instance $`j`$: it simulates Instances
$`0, \ldots, j-1`$ honestly using the random chain values it chose (which it knows), and simulates Instances
$`j+1, \ldots, q-1`$ with real KT128 evaluations. An adversary distinguishing these two hybrids implies an adversary
against the KDF security of Instance $`j`$, because $`\mathit{cv}_j`$ is the output of a random oracle
(`0x20`, or `0x24` for `Ratchet`) on a transcript containing an unpredictable input (either fresh key material in
Instance 0, or the already-random $`\mathit{cv}_{j-1}`$ from the hybrid assumption). For `Ratchet`, only a single
oracle is evaluated and no operational output is produced, so the chain independence condition (§8.4) is vacuously
satisfied. The RO-KDF bound applies in all cases. By a union bound over the $`q`$
transitions:

```math
\mathrm{Adv}^{\mathrm{chain}}(\mathcal{A}) \leq q \cdot \varepsilon_{\mathrm{kdf}}
```

**Chain value collisions.** Each chain value is $`H = 64`$ bytes (512 bits). The birthday bound for collisions across
$`q`$ instances is $`q^2 / 2^{8H+1} = q^2 / 2^{513}`$. A collision would cause two instances to share identical
subsequent transcripts. For $`q \leq 2^{48}`$, this probability is $`2^{-417}`$, far below the 128-bit security
target.

### 8.6 Per-Operation Security

The following table summarizes the security properties provided by each operation. All confidentiality and
pseudorandomness claims require that the transcript contains at least one unpredictable input.

| Operation   | Property                | Precondition                      |
|-------------|-------------------------|-----------------------------------|
| Derive      | PRF output, collision resistance, preimage resistance | Unpredictable input (PRF only) |
| Ratchet     | Forward secrecy         | Prior transcript state erased     |
| Mask/Unmask | IND-CPA confidentiality | Unpredictable input in transcript |
| Seal/Open   | IND-CCA2 + CMT-4       | Unpredictable input in transcript |
| Fork        | Branch independence     | Always (ordinals ensure distinctness) |

**Derive.** The output is produced by KT128 with customization string `0x21` on the current transcript. Collision
resistance and preimage resistance follow directly from KT128 (§8.1), regardless of whether the transcript contains
unpredictable inputs. When the transcript does contain an unpredictable input, KDF security (§8.3) ensures the output
is indistinguishable from random; combined with injectivity of the encoding (which guarantees distinct transcripts produce independent outputs), this
gives PRF security.

**Ratchet.** The chain value (customization string `0x24`) is the sole output. The pre-ratchet transcript is
unrecoverable from the chain value by KT128 preimage resistance. Forward secrecy holds provided the implementation
securely discards all state associated with the pre-ratchet transcript. Without secure erasure, an adversary who
compromises the implementation's internal state may be able to recover prior keys.

**Mask / Unmask.** The TW128 key is derived via KT128 with customization string `0x22`. Under the RO-KDF argument
(§8.3), this key is indistinguishable from a uniformly random `C`-byte string as long as the transcript contains an
unpredictable input. By the TW128 IND-CPA assumption (§8.1), `Mask` provides IND-CPA confidentiality.

The tag is a deterministic function of the TW128 key, which is derived from a different customization string
(`0x22`) than the chain value (`0x20`). By chain independence (§8.4), the tag reveals no information about the chain
value, preserving composition. If the
ciphertext is tampered with, the sender and receiver compute different tags, causing their transcripts to diverge and
all subsequent operations to produce different results. However, `Mask` alone does not provide integrity guarantees.
Applications requiring integrity should use `Seal` or authenticate the ciphertext externally.

**Seal / Open.** The security of `Seal` follows in two steps. First, the TW128 key is derived via customization
string `0x23`, and the RO-KDF argument (§8.3) establishes that this key is indistinguishable from a uniformly random
$`C`$-byte string. Second, TW128 under a uniformly random key provides IND-CPA and INT-CTXT (§8.1), which together
imply IND-CCA2 (Bellare and Namprempre, ASIACRYPT 2000, Theorem 3.2). Chain independence (§8.4) ensures that subsequent
protocol outputs — derived from the chain value under a different customization string (`0x20`) — reveal no information
about the Seal key, so the IND-CCA2 guarantee is not weakened by the adversary's view of later operations.

For Seal to achieve CMT-4 committing security at the protocol level, two conditions must hold. First, distinct
transcripts must produce distinct keys: collision resistance of KT128 (§8.1) ensures this except with negligible
probability (bounded by the collision term in §8.7), so an adversary cannot produce a single ciphertext that is valid
under two distinct transcript histories. Second, under each derived key, TW128 must be CMT-4 (§8.1), so the ciphertext
does not admit two valid openings under distinct $`(\mathit{key}, \mathit{plaintext})`$ pairs. KDF security (§8.3)
ensures each key is indistinguishable from a uniformly random string, satisfying TW128's key distribution assumption.

`Open` advances the transcript unconditionally with the computed tag. On verification failure, the receiver's computed
tag differs from the sender's, and the chain frame absorbs a different value. All subsequent operations produce
different results from the sender's.

**Fork.** `Fork` does not finalize. All $`N + 1`$ branches share identical transcript up to the fork point and diverge
via their ordinals. Since each branch receives a distinct ordinal and the encoding is injective (§8.3), all N+1 branches
produce distinct transcripts, guaranteeing independent outputs at any subsequent finalization.

### 8.7 Concrete Security Bound

The reduction has three layers: replace KT128 with a random oracle (indifferentiability), apply the RO-KDF argument per
instance with inductive composition (§§8.3–8.5), and invoke TW128's IND-CPA, INT-CTXT, and CMT-4 properties
(§8.1).

**Domain separation.** Operation codes are embedded in the transcript (the message $`M`$ to KT128), while customization
strings are encoded separately via KT128's input format (RFC 9861, §3.2). The two are structurally separate and cannot
interfere. The five Thyrse customization bytes (`0x20`–`0x24`) are mutually distinct, ensuring that the KT128 evaluations
within each finalization target independent random oracles.

**Parameters.**

| Symbol | Meaning                                                                        |
|--------|--------------------------------------------------------------------------------|
| $`q`$  | Total number of finalizing operations across the protocol lifetime             |
| $`\sigma`$ | Total data complexity: number of Keccak-p[1600,12] calls made by the protocol |
| $`t`$  | Adversary's offline computation budget in Keccak-p[1600,12] calls              |
| $`S`$  | Number of forgery attempts against `Seal`/`Open`                               |
| $`c`$  | TurboSHAKE128 capacity = 256 bits                                              |
| $`H`$  | Chain value length = 512 bits                                                  |

The data complexity $`\sigma`$ counts all Keccak-p[1600,12] calls made by the protocol, including both KT128
finalizations and TW128 encryption/decryption. All share the same ideal permutation and contribute to the global
indifferentiability budget.

**Combined bound.**

```math
\varepsilon_{\mathrm{total}} \leq \varepsilon_{\mathrm{perm}} + \frac{2(\sigma + t)^2}{2^{c+1}} + q \cdot \varepsilon_{\mathrm{kdf}} + \frac{q^2}{2^{8H+1}} + \varepsilon_{\mathrm{tw}}
```

where:

- $`\varepsilon_{\mathrm{perm}}`$ is the advantage of distinguishing Keccak-p[1600,12] from a random permutation
  (conjectured negligible).
- $`2(\sigma + t)^2 / 2^{c+1} = 2(\sigma + t)^2 / 2^{257}`$ is the sponge indifferentiability term, covering all
  Keccak-p evaluations globally (Thyrse backbone and TW128 internals). The factor of 2 arises from the Sakura
  composition: the combined indifferentiability of KT128 (tree hash on TurboSHAKE128) is bounded by
  $`q_{\mathrm{tree}}^2 / 2^{c+1} + (\sigma + t)^2 / 2^{c+1}`$, which simplifies to $`2(\sigma + t)^2 / 2^{c+1}`$
  since $`q_{\mathrm{tree}} \leq \sigma`$.
- $`q \cdot \varepsilon_{\mathrm{kdf}}`$ is $`q`$ times the per-instance RO-KDF bound, which depends on the
  unpredictability of the caller's key material. For key material with $`\kappa`$ bits of min-entropy,
  $`\varepsilon_{\mathrm{kdf}} \leq 2 \cdot t / 2^{\kappa}`$ (the factor of 2 is from BCFG25 Proposition 7;
  $`t`$ upper-bounds the number of random oracle queries, which is at most the Keccak-p budget). In the chain setting, Theorem 8's sum over sources is
  dominated by the caller's weakest key material: the chain value source contributes at most $`t / 2^{512}`$
  (negligible), so the per-instance bound collapses to the weakest caller-supplied source.
- $`q^2 / 2^{8H+1} = q^2 / 2^{513}`$ bounds chain value collisions (§8.5).
- $`\varepsilon_{\mathrm{tw}}`$ is the combined advantage against TW128's IND-CPA, INT-CTXT, and CMT-4 properties.
  See the TW128 specification for the concrete bound; the dominant term is $`S / 2^{8C} = S / 2^{256}`$ for forgery
  resistance.

**Numerical evaluation.** For typical parameters — $`q \leq 2^{48}`$ finalizations, $`\sigma + t \leq 2^{64}`$ total
Keccak-p calls, $`S \leq 2^{48}`$ forgery attempts, and 256-bit key material ($`\kappa = 256`$):

- Indifferentiability: $`2(2^{64})^2 / 2^{257} = 2^{-128}`$
- RO-KDF: $`2^{48} \cdot 2 \cdot 2^{64} / 2^{256} = 2^{-143}`$
- Chain collisions: $`(2^{48})^2 / 2^{513} = 2^{-417}`$
- TW128 forgery: $`2^{48} / 2^{256} = 2^{-208}`$

The indifferentiability term dominates. The 128-bit security target is met as long as the caller ensures
$`\varepsilon_{\mathrm{kdf}} \leq 2^{-128}`$ (i.e., the original key material has at least 128 bits of min-entropy)
and the total data complexity satisfies $`\sigma + t \leq 2^{64}`$.

### 8.8 Forward Secrecy

Every finalizing operation in Thyrse discards the pre-finalization transcript and replaces it with
a chain frame containing a 512-bit pseudorandom chain value. This means every finalization is inherently a ratchet:
the session state after any finalization contains no algebraic structure exploitable in a multi-target search. An
adversary targeting pre-finalization key material must do so before the finalization occurs. The explicit `Ratchet`
operation (§8.6) is distinguished only by producing no operational output, which eliminates the risk of leaking
information through the output channel. Forward secrecy holds provided the implementation securely erases
pre-finalization state (§8.6).

### 8.9 Multi-User Security

The bound in §8.7 covers a single Thyrse instance. This section extends the analysis to a setting with $`U`$
independent instances. We consider two cases: one-shot instances (a single finalization, as in a standalone AEAD or
KDF) and running sessions (a chain of finalizations).

#### 8.9.1 One-Shot Instances

When Thyrse is used as a one-shot construction (Init, Mix key material, then a single Mask, Seal, or Derive), each instance
evaluates exactly one KDF link. The per-instance security reduces directly to the single-instance bound in §8.7. In a
multi-user setting with $`U`$ one-shot instances and an adversary making $`t`$ offline queries against key material
with $`\kappa`$ bits of min-entropy:

**Multi-target key recovery.** The adversary may attempt to predict any of the $`U`$ initial keys. By a standard
hybrid argument over instances:

```math
\varepsilon_{\mathrm{mu\text{-}key}} \leq U \cdot 2t / 2^{\kappa}
```

This is the multi-target analogue of the single-instance RO-KDF bound. The factor of $`U`$ is tight for one-way
primitives under black-box reductions (Bellare, Boldyreva, and Micali, "Public-key encryption in a multi-user
setting," EUROCRYPT 2000; Biham, "How to forge DES-encrypted messages in $`2^{28}`$ steps," 1996).

**Cross-instance output collisions.** If two one-shot instances produce the same chain value, their outputs under the
same customization string will collide:

```math
\varepsilon_{\mathrm{mu\text{-}coll}} \leq \frac{U^2}{2^{8H+1}} = \frac{U^2}{2^{513}}
```

For $`U = 2^{48}`$: $`2^{96} / 2^{513} = 2^{-417}`$.

**Combined one-shot bound:**

```math
\varepsilon_{\mathrm{one\text{-}shot}} \leq \varepsilon_{\mathrm{perm}} + \frac{2(\sigma_{\mathrm{total}} + t)^2}{2^{257}} + \frac{U \cdot 2t}{2^{\kappa}} + \frac{U^2}{2^{513}} + \varepsilon_{\mathrm{tw}}
```

The multi-target key recovery term dominates the user-scaling terms. For 256-bit keys and $`U = 2^{48}`$ one-shot
instances: $`\varepsilon_{\mathrm{mu\text{-}key}} = 2^{48} \cdot 2^{65} / 2^{256} = 2^{-143}`$.

#### 8.9.2 Running Sessions

When Thyrse is used as a running session with multiple finalizations, every finalizing operation replaces the chain
value (§8.8). There is no fixed per-session key that persists across evaluations. In the chain classification of
Mattsson ("Security of Symmetric Ratchets and Key Chains," 2024, §3.1), Thyrse is comparable to an ω-chain
(randomized key chain where $`k_{i+1} = \mathrm{KDF}(k_i, r_i, n)`$) with three structural improvements: the chain
state is 512 bits rather than the output key size, each link is a full n-KDF evaluation with a recoverable encoding
(giving KDF security per §8.3, not only one-way security), and the per-link randomization comes from the full
transcript rather than a single random value.

**No per-session key to target.** In a standard multi-user AEAD analysis, the adversary targets $`U`$ fixed keys,
each encrypting many messages, and the multi-user advantage scales with $`U`$ because the adversary gets multiple
observations under each key. Thyrse's ratcheting structure (§8.8) eliminates this attack surface: the chain value
after each finalization is fresh and used exactly once. The multi-target surface consists only of the $`U`$ initial
key material values, not $`U \cdot q`$ chain values. This corresponds to the observation in Collins, Riepel, and Tran
("On the Tight Security of the Double Ratchet," CCS 2024, Theorem 5) that for composed ratchet protocols, the
symmetric-key multi-session cost reduces to a collision term on the root key space plus the multi-instance security of
the underlying primitives. In Thyrse's case, KT128 is modeled as a random oracle, so the multi-instance symmetric-key
cost is absorbed into the indifferentiability term.

**Cross-session chain collisions.** With $`Q`$ total chain values across all sessions ($`Q \leq U \cdot q`$ for $`q`$
finalizations per session), the birthday bound for a cross-session collision is:

```math
\varepsilon_{\mathrm{mu\text{-}chain}} \leq \frac{Q^2}{2^{513}}
```

A collision causes transcript convergence: two sessions sharing a chain value will produce identical outputs from that
point forward (a privacy failure). Unlike key reuse in multi-user AEAD, each colliding chain value is still used
exactly once, so the collision does not amplify further attacks. For $`U = 2^{32}`$ sessions with $`q = 2^{32}`$
finalizations each: $`2^{128} / 2^{513} = 2^{-385}`$.

**Shared ideal permutation.** All instances share the same Keccak-p[1600,12] permutation. The indifferentiability
bound is global: $`2(\sigma_{\mathrm{total}} + t)^2 / 2^{257}`$ where $`\sigma_{\mathrm{total}}`$ counts Keccak-p calls
across all instances. There is no per-instance multiplier. Daemen, Mennink, and Van Assche ("Full-State Keyed Duplex
With Built-In Multi-User Support," ASIACRYPT 2017, Theorem 1) prove that the full-state keyed duplex achieves
multi-target security bounds that are largely independent of the number of users: the only user-dependent term is
$`q_{\mathrm{iv}} N / 2^k`$ for sessions sharing initialization vectors, which does not apply when each Thyrse instance
is initialized with independent key material.

**Combined running-session bound:**

```math
\varepsilon_{\mathrm{session}} \leq \varepsilon_{\mathrm{perm}} + \frac{2(\sigma_{\mathrm{total}} + t)^2}{2^{257}} + \frac{U \cdot 2t}{2^{\kappa}} + \frac{Q^2}{2^{513}} + \varepsilon_{\mathrm{tw}}
```

The formula is identical to the one-shot bound with $`Q`$ replacing $`U`$ in the collision term, reflecting that
running sessions produce more chain values. The multi-target key recovery term still scales with $`U`$ (not $`Q`$)
because only the initial key material is a static multi-target surface.

**Numerical evaluation.** For $`U = 2^{32}`$ running sessions, $`q = 2^{32}`$ finalizations per session,
$`\sigma_{\mathrm{total}} + t \leq 2^{80}`$, $`S = 2^{48}`$ total forgery attempts, and 256-bit key material:

- Indifferentiability: $`2 \cdot 2^{160} / 2^{257} = 2^{-96}`$
- Multi-target key recovery: $`2^{32} \cdot 2^{81} / 2^{256} = 2^{-143}`$
- Cross-session chain collisions: $`2^{128} / 2^{513} = 2^{-385}`$
- TW128 forgery: $`2^{48} / 2^{256} = 2^{-208}`$

The indifferentiability term dominates. The aggregate data complexity ($`\sigma_{\mathrm{total}}`$) grows with the
number of instances, reducing the effective security margin from the single-instance 128 bits to 96 bits at
$`U = 2^{32}`$ with $`2^{80}`$ total Keccak-p calls. Callers requiring 128-bit multi-user security at this scale
should bound $`\sigma_{\mathrm{total}} + t \leq 2^{64}`$, which constrains the per-instance data complexity.

## 9. Implementation Notes

### 9.1 Incremental Hashing

Although the transcript is described as a byte string that is hashed in its entirety at each finalization, an
implementation SHOULD use an incremental KT128 implementation. Non-finalizing operations (`Init`, `Mix`, `Fork`) feed
their frames into the running KT128 state. Finalizing operations clone the state and finalize the clones with their
respective customization strings. This avoids re-hashing the full transcript on each finalization.

The two KT128 evaluations at each finalization (chain value + output/key) require one clone and two independent
finalizations, which may execute in parallel. Note that KT128 can absorb up to 168 bytes of input before performing its
first expensive permutation, which is sufficient for a typical AEAD header (`Init` + `Mix(key)` + `Mix(nonce)` +
`Mix(ad)` with a 32-byte key, 12-byte nonce, and short AD).

### 9.2 Constant-Time Operation

Implementations MUST ensure constant-time processing for all secret data. KT128 and TW128 MUST not branch on any
input values. Tag verification in `Open` MUST use constant-time comparison.

### 9.3 Memory Sanitization

**Plaintext on failed `Open`.** `Open` decrypts ciphertext before verifying the tag. If verification fails, the
plaintext buffer contains unauthenticated data that SHOULD be zeroed before returning. Implementations that decrypt
in-place SHOULD overwrite the buffer with zeros (not with the original ciphertext, which may itself be
attacker-controlled). Callers MUST NOT read or act on plaintext from a failed `Open`.

**Protocol state.** The `Clear` operation (§7.8) zeros the internal state, buffered key material, and stored `Init`
label. Implementations SHOULD also zero derived TW128 keys and intermediate chain values as soon as they are no
longer needed. For forward secrecy to hold after any finalization, the pre-finalization state SHOULD be erased;
retaining it in memory weakens the forward secrecy guarantee.

**Registers.** Implementations SHOULD clear SIMD and general-purpose registers that held secret data (key material,
chain values, intermediate KT128 or TW128 state) before returning from operations.

**Language-level considerations.** In languages with garbage collection or compiler optimizations that may elide stores
to dead memory, implementations SHOULD use platform-specific secure-zeroing primitives (e.g., `explicit_bzero`,
`SecureZeroMemory`, `volatile` writes) to ensure that sensitive data is actually erased.

### 9.4 Data Limits

**Proof model limits vs. practical limits.** The indifferentiability term in §8.7
($`2(\sigma + t)^2 / 2^{c+1}`$) is a limit of the proof technique, not a known weakness in the construction. It
bounds the advantage of an adversary who can distinguish the Keccak-p[1600,12] sponge from a random oracle, which is
the model under which KT128's security is proven. The $`\sigma + t \leq 2^{64}`$ threshold at which this bound reaches
$`2^{-128}`$ is shared by all constructions built on the same permutation (SHA-3, SHAKE, TurboSHAKE, KT128, TW128).
At 168 bytes per sponge block, this corresponds to roughly $`2^{71}`$ bytes (2.8 exabytes). Beyond this threshold, the
proof no longer guarantees 128-bit security, but this does not mean the construction becomes insecure; it means the
reduction to the ideal permutation model is no longer tight enough to make the claim. No known attack exploits this
gap.

**Per-operation costs.** A non-finalizing operation (Init, Mix) appends to the running transcript without forcing a
permutation; it contributes $`\lceil \text{frame size} / 168 \rceil`$ sponge blocks to $`\sigma`$. Each finalizing
operation (Derive, Ratchet, Mask, Seal) evaluates KT128 twice (chain value and operational output), costing at least 2
Keccak-p calls plus absorption of the transcript. Mask and Seal additionally invoke TW128, whose cost is
proportional to the plaintext length.

**Thyrse-specific limits.** Within Thyrse itself, there is no per-session key lifetime concern analogous to AEAD nonce
exhaustion. Every finalizing operation ratchets the protocol state (§8.8), and the chain collision bound
($`q^2 / 2^{513}`$, §8.5) remains negligible for any practical number of finalizations. Implementations do not need to
enforce session-level data limits or rekeying intervals.

## 10. Typical Usage: AEAD

A standard AEAD construction:

<!-- begin:code:ref/thyrse.py:usage_aead -->
```python
def _example_aead(key_material, nonce, associated_data, plaintext):
    p = Protocol()
    p.init(b"com.example.myprotocol")
    p.mix(b"key", key_material)
    p.mix(b"nonce", nonce)
    p.mix(b"ad", associated_data)
    ciphertext_tag = p.seal(b"message", plaintext)
```
<!-- end:code:ref/thyrse.py:usage_aead -->

Decryption:

<!-- begin:code:ref/thyrse.py:usage_aead_decrypt -->
```python
def _example_aead_decrypt(key_material, nonce, associated_data, ciphertext, tag):
    p = Protocol()
    p.init(b"com.example.myprotocol")
    p.mix(b"key", key_material)
    p.mix(b"nonce", nonce)
    p.mix(b"ad", associated_data)
    plaintext = p.open(b"message", ciphertext, tag)
```
<!-- end:code:ref/thyrse.py:usage_aead_decrypt -->

## 11. References

- Alwen, J., Coretti, S., and Dodis, Y. "The Double Ratchet: Security Notions, Proofs, and Modularization for the
  Signal Protocol." EUROCRYPT 2019. Formalizes PRF-PRNG (KDF chain) as a cryptographic primitive (Definitions 16–17).
- Backendal, M., Clermont, S., Fischlin, M., and Günther, F. "Key Derivation Functions Without a Grain of Salt."
  Eurocrypt 2025 / IACR ePrint 2025/657. Defines the RO-KDF construction requiring recoverable encoding.
- Bellare, M., Boldyreva, A., and Micali, S. "Public-key encryption in a multi-user setting: Security proofs and
  improvements." EUROCRYPT 2000. Establishes the standard multi-target reduction for one-way primitives.
- Biham, E. "How to forge DES-encrypted messages in 2^28 steps." Technical Report CS 884, Technion, 1996.
  Demonstrates multi-target attacks exploiting the linear scaling of advantage with the number of targets.
- Bellare, M. and Hoang, V. T. "Efficient schemes for committing authenticated encryption." EUROCRYPT 2022. Defines
  the CMT-4 committing security notion.
- Bellare, M. and Namprempre, C. "Authenticated Encryption: Relations among Notions and Analysis of the Generic
  Composition Paradigm." ASIACRYPT 2000. Proves that IND-CPA + INT-CTXT implies IND-CCA2.
- Collins, D., Riepel, D., and Tran, S. A. O. "On the Tight Security of the Double Ratchet." ACM CCS 2024. Proves
  multi-session security of the Double Ratchet via modular reduction to CKA, FS-AEAD, and PRF-PRNG components.
- Daemen, J., Mennink, B., and Van Assche, G. "Full-State Keyed Duplex With Built-In Multi-User Support." ASIACRYPT
  2017. Proves multi-target security bounds for the full-state keyed duplex that are largely independent of the number
  of users.
- Mattsson, J. P. "Security of Symmetric Ratchets and Key Chains." 2024. Categorizes key chain constructions
  (ρ-, ξ-, ω-, and π-chains) and analyzes their multi-connection collision properties.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "On the Indifferentiability of the Sponge Construction."
  IACR ePrint 2008/014. Eurocrypt 2008. Proves sponge indifferentiability from a random oracle under the ideal
  permutation model.
- Bertoni, G., Daemen, J., Peeters, M., and Van Assche, G. "Sakura: a flexible coding for tree hashing." IACR ePrint
  2013/231. Applied Cryptography and Network Security (ACNS) 2014. Defines and proves soundness of the Sakura tree
  hash coding convention.
- Bertoni, G., Daemen, J., Peeters, M., Van Assche, G., Van Keer, R., and Viguier, B. "KangarooTwelve: fast hashing
  based on Keccak-p." IACR ePrint 2016/770. Applied Cryptography and Network Security (ACNS) 2018. Specifies KT128 as
  a concrete application of Sakura encoding.
- Maurer, U., Renner, R., and Holenstein, C. "Indifferentiability, Impossibility Results on Reductions, and
  Applications to the Random Oracle Methodology." TCC 2004. Defines indifferentiability and proves the composition
  theorem.
- NIST SP 800-185: SHA-3 Derived Functions (`left_encode`, `right_encode`, `encode_string`).
- RFC 9861: KangarooTwelve and TurboSHAKE.
- TW128128 specification. Defines the tree-parallel authenticated encryption scheme used by Mask and Seal. Provides
  IND-CPA, INT-CTXT, CMT-4, and tag PRF security claims referenced in §8.1.

## 12. Test Vectors

<!-- begin:vectors:docs/thyrse-test-vectors.json:thyrse -->
All values are hex-encoded. All test vectors use `Init` label `"test.vector"`. Byte string literals are shown in hex as
`(hex)`.

### 16.1 Init + Derive

Minimal protocol producing output.

```python
p = Protocol()
p.init(b"test.vector")
output = p.derive(b"output", 32)
```

| Field | Value |
|-------|-------|
| Derive output | `25feba088971a4b573101369ea1c8d83e6f102c2dc46e5cceb81a0b97fca514c` |

### 16.2 Init + Mix + Mix + Derive

Multiple non-finalizing operations before `Derive`.

```python
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
p.mix(b"nonce", b"test-nonce-value")
output = p.derive(b"output", 32)
```

| Field | Value |
|-------|-------|
| Derive output | `0db4090efec2ba935dac63a18d88df04859d1dedf4a60f428393674520b67e39` |

### 16.3 Init + Mix + Seal + Derive

Full AEAD followed by `Derive`.

```python
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
ct_tag = p.seal(b"message", b"hello, world!")
output = p.derive(b"output", 32)
```

| Field | Value |
|-------|-------|
| Seal output (ct ‖ tag) | `dde795eebaaa663b55e904c1e4da1c6c6f1c770b9c90fd17b8add38741dd5e4c821ad0e5aeb4bbfbc18d89ebe4` |
| Derive output | `e6a99cd5ac77af8370dd09e5f1ea020b1ded0a7415a9dadcbe6133e917dd2498` |

### 16.4 Init + Mix + Mask + Seal

Combined unauthenticated and authenticated encryption.

```python
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
ct = p.mask(b"unauthenticated", b"mask this data")
ct_tag = p.seal(b"authenticated", b"seal this data")
```

| Field | Value |
|-------|-------|
| Mask output (ct) | `21fc87f3008b3cff62fb2584c970` |
| Seal output (ct ‖ tag) | `f078ea89c7dea34a821c8470544ec5a70061c75aa9de8a1d49e4a9e816455ca54f78e50a2a1981d1c0a47cfe4d20` |

### 16.5 Ratchet + Derive

Baseline `Derive` output without `Ratchet`, for comparison with §16.5.2. `Derive` output changes after `Ratchet`, demonstrating forward secrecy.

```python
# Without Ratchet
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
output_no_ratchet = p.derive(b"output", 32)

# With Ratchet
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
p.ratchet(b"forward-secrecy")
output_after_ratchet = p.derive(b"output", 32)
```

| Field | Value |
|-------|-------|
| Derive (no Ratchet) | `b20333efd472bf1cafbdfcc7c4aef46ca9984b768dbf84e33006024bead07dcf` |
| Derive (after Ratchet) | `23be92e694890a8b3d6fb5b4885b3b5a63539ad8da6fc5e8e20cf34728dbeb91` |

### 16.6 Fork + Derive

`Fork` with two branches, each producing `Derive`. All three outputs are independent.

```python
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
clones = p.fork(b"role", b"prover", b"verifier")
base_output = p.derive(b"output", 32)        # base (ordinal 0)
clone_1_output = clones[0].derive(b"output", 32)  # "prover" (ordinal 1)
clone_2_output = clones[1].derive(b"output", 32)  # "verifier" (ordinal 2)
```

| Branch | Derive output |
|--------|---------------|
| Base (ordinal 0) | `53fa58633361a67384c7a6d8df0e6163dac581024e9786856442edf13e5b787c` |
| Clone 1 / "prover" (ordinal 1) | `329696ce84ae7aef8577db9841d82956b60f9f7ce38449d8b83092f3a46a89ad` |
| Clone 2 / "verifier" (ordinal 2) | `19644cc5d0a5bc8f52eb647a581b85ba868ce0cb3561f8d2a58f1bf6ed1a3e82` |

### 16.7 Seal + Open Round-Trip

Successful authenticated encryption and decryption. Post-operation `Derive` outputs match.

```python
# Sender
sender = Protocol()
sender.init(b"test.vector")
sender.mix(b"key", b"test-key-material")
sender.mix(b"nonce", b"test-nonce-value")
sender.mix(b"ad", b"associated data")
ct_tag = sender.seal(b"message", b"hello, world!")

# Receiver
receiver = Protocol()
receiver.init(b"test.vector")
receiver.mix(b"key", b"test-key-material")
receiver.mix(b"nonce", b"test-nonce-value")
receiver.mix(b"ad", b"associated data")
ct, tag = ct_tag[:-32], ct_tag[-32:]
pt = receiver.open(b"message", ct, tag)
confirm = receiver.derive(b"confirm", 32)
```

| Field | Value |
|-------|-------|
| Seal output (ct ‖ tag) | `1383ffe1d63304655b9b94ae27f2a50ea1734e2df148381c2080d70ad86bac40e84d08e43b48b0b9f4a106156a` |

### 16.8 Seal + Open with Tampered Ciphertext

`Open` returns ⊥ and subsequent `Derive` outputs diverge from the sender.

```python
# Sender
sender = Protocol()
sender.init(b"test.vector")
sender.mix(b"key", b"test-key-material")
sender.mix(b"nonce", b"test-nonce-value")
ct_tag = sender.seal(b"message", b"hello, world!")
sender_after = sender.derive(b"after", 32)

# Receiver — tampered[0] ^= 0xff
receiver = Protocol()
receiver.init(b"test.vector")
receiver.mix(b"key", b"test-key-material")
receiver.mix(b"nonce", b"test-nonce-value")
tampered = bytearray(ct_tag)
tampered[0] ^= 0xff
ct, tag = bytes(tampered[:-32]), bytes(tampered[-32:])
pt = receiver.open(b"message", ct, tag)  # returns None
receiver_after = receiver.derive(b"after", 32)
```

| Field | Value |
|-------|-------|
| Seal output (ct ‖ tag) | `6e73c8fb8e615ac7d3bfdeaaa7e8e1af189b97db42b2870b693c5faf0be6bbc8345d8830401a53acccc756500a` |
| Open result | ⊥ (authentication failed) |

### 16.9 Multiple Seals in Sequence

First of three sequential Seals. Each derives a different key because the transcript advances via tag absorption.

```python
p = Protocol()
p.init(b"test.vector")
p.mix(b"key", b"test-key-material")
p.mix(b"nonce", b"test-nonce-value")
ct_tag_1 = p.seal(b"msg", b"first message")
ct_tag_2 = p.seal(b"msg", b"second message")
ct_tag_3 = p.seal(b"msg", b"third message")
```

| Seal | Output (ct ‖ tag) |
|------|-------------------|
| 1 | `f58f5895735ec5679a75651160f0e2b29ea495e5a13e482d22c5bd1f58c75a345a9dacbf4205022b27f809fcc2` |
| 2 | `2b6b64822aa4ac6716aaf6226e20d4d9f1c6ac6bafbe00761b03663b3e574d91be5fa8918945fa311214cfa83e1b` |
| 3 | `86de20dad1084ed184d23aa56a3c3001a468b67c6687b2ab93e5b640008b6c912f88b6a3a88cd4283a7719c273` |
<!-- end:vectors:docs/thyrse-test-vectors.json:thyrse -->
