# TKDF: Transcript-KDF Encoding

<table>
  <tr><th>Status</th><td>Draft</td></tr>
  <tr><th>Date</th><td>2026-03-07</td></tr>
</table>

## 1. Purpose

This document defines TKDF (Transcript-KDF), a recoverable encoding for transcript frames. TKDF satisfies
the requirements of the RO-KDF construction of Backendal, Clermont, Fischlin, and Günther (Eurocrypt 2025,
ePrint 2025/657). The encoding is designed for use with a hash function H that is indifferentiable from a
random oracle.

Throughout this document, $`|x|`$ denotes the length of byte string $`x`$ in bytes.

## 2. Background: RO-KDF Requirements

The RO-KDF construction (BCFG25, §5.1, Theorem 8) derives keys by evaluating a random oracle
$`\mathrm{H}_T`$ on a recoverable encoding of the KDF inputs:

```math
K \leftarrow \mathrm{H}_T(\langle \sigma_1, c_1, \sigma_2, c_2, \ldots, \sigma_n, c_n, L \rangle)
```

The encoding $`\langle \cdot \rangle`$ must satisfy two properties for the reduction to hold:

1. **Injectivity.** Distinct input tuples produce distinct encoded strings. This ensures that distinct KDF
   evaluations correspond to distinct random oracle queries.

2. **Efficient decodability.** There exists a deterministic polynomial-time algorithm $`\mathrm{Parse}`$ such that
   $`\mathrm{Parse}(\langle x \rangle) = x`$ for all $`x`$ in the domain, and $`\mathrm{Parse}`$ terminates in polynomial time
   on all inputs (including strings not in the image of the encoding). This ensures that the simulator
   $`\mathcal{B}_i`$ in the proof of Theorem 8 can extract components from random oracle queries — including
   adversarially constructed queries to $`\mathrm{H}_T`$ — to determine whether they contain the target secret,
   and if so, to call the prediction oracle.

We call an encoding satisfying both properties **recoverable**. The encoding need not be left-to-right
parseable; the simulator receives the complete encoded string and may parse it in any order.

We restate Theorem 8 (adapted to our notation). Let $`\mathrm{H}_T`$ be a random oracle (with output length
$`hl`$ for T = NOF, unbounded for T = XOF). Let $`\mathbf{\Sigma} = (\Sigma_1, \ldots, \Sigma_r)`$ be a source
collection with mapping $`\Sigma`$-map, each source outputting at most $`u`$ elements. Let $`\mathit{req}`$ be
$`\mathit{req}_N`$ for T = NOF and $`\mathit{req}_X`$ for T = XOF. Then for any adversary $`\mathcal{A}`$
against the KDF security of $`\mathrm{RO\text{-}KDF}_n[\mathrm{H}_T]`$:

```math
\mathrm{Adv}^{\mathrm{kdf}}_{\mathrm{RO\text{-}KDF}_n[\mathrm{H}_T], \mathbf{\Sigma}, \mathit{req}}(\mathcal{A}) \leq 2 \cdot \sum_{i=1}^{r} \mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}(\mathcal{B}_i)
```

for adversaries $`\mathcal{B}_i`$ with roughly the same running time as $`\mathcal{A}`$. The factor of 2 arises
from Proposition 7 of BCFG25, which shows that KDF queries can be simulated via $`\mathrm{Ro\$\text{-}KDF}`$ oracle queries.

The requirement $`\mathit{req}_X`$ combines two conditions: (1) each key material source $`\Sigma_i`$ is
**source-unpredictable** — no efficient adversary given a prediction oracle can guess $`\Sigma_i`$'s output
with non-negligible probability — and (2) for XOFs, the freshness condition $`\mathit{req}_{\mathrm{XOF}}`$: the
adversary cannot make two challenge queries that differ only in output length. When $`\mathrm{H}_T`$ is a XOF,
any protocol instantiating this encoding must ensure that identical transcripts are never evaluated with the
same domain separation parameters but different output lengths. Since distinct domain separation parameters
select independent random oracles (§9), $`\mathit{req}_{\mathrm{XOF}}`$ applies independently within each oracle.

## 3. Primitives from NIST SP 800-185

We use two encodings from NIST SP 800-185:

**`left_encode(x)`**: Encodes a non-negative integer $`x`$ as a byte string consisting of the byte count of
the big-endian encoding followed by the big-endian encoding of $`x`$. The result is self-delimiting when
parsed left-to-right: the first byte $`n`$ gives the number of subsequent bytes to read. $`n`$ is in the range
$`[1, 255]`$.

**`right_encode(x)`**: Encodes a non-negative integer $`x`$ as a byte string consisting of the big-endian
encoding of $`x`$ followed by the byte count of the encoding. The result is self-delimiting when parsed
right-to-left: the last byte $`n`$ gives the number of preceding bytes to read. $`n`$ is in the range
$`[1, 255]`$.

Both encodings represent the same integer; they differ only in the position of the length byte. Both are
injective: distinct integers produce distinct encoded byte strings.

**`encode_string(b)`**: For a byte string $`b`$, $`\mathrm{encode\_string}(b) = \mathrm{left\_encode}(|b| \times 8) \mathbin\| b`$.
This is the `encode_string` function of NIST SP 800-185. The bit-length of $`b`$ is left-encoded as a prefix,
making the encoding self-delimiting when parsed left-to-right. `encode_string` is injective: distinct byte
strings produce distinct encodings.

## 4. Frame Encoding

A **frame** is a triple $`(op, label, value)`$ where $`op`$ is a single byte, $`label`$ is a byte string, and $`value`$
is a byte string of arbitrary length (not necessarily known in advance). The frame encoding is:

```math
\mathrm{encode\_frame}(op, label, value) = op \mathbin\| \mathrm{encode\_string}(label) \mathbin\| value
```

A single frame is not self-delimiting: the end of $`value`$ cannot be determined without external boundary
information. This is by design — it allows $`value`$ to be streamed without knowing its length in advance.

## 5. Transcript Encoding

A **transcript** is a sequence of frames $`F_0, F_1, \ldots, F_{m-1}`$ where $`F_i = (op_i, label_i, value_i)`$.
The empty sequence ($`m = 0`$) is valid and encodes to the empty string.

Frames are concatenated with **position markers** interleaved between them. When a frame ends, the byte
offset of the frame's start position is appended as a `right_encode` value. This provides the structural
information needed to recover frame boundaries.

```math
\mathrm{encode\_transcript}(F_0, \ldots, F_{m-1}) = \mathrm{encode\_frame}(F_0) \mathbin\| \mathrm{right\_encode}(s_0) \mathbin\| \mathrm{encode\_frame}(F_1) \mathbin\| \mathrm{right\_encode}(s_1) \mathbin\| \cdots \mathbin\| \mathrm{encode\_frame}(F_{m-1}) \mathbin\| \mathrm{right\_encode}(s_{m-1})
```

where $`s_i`$ is the byte offset in the encoded transcript at which $`\mathrm{encode\_frame}(F_i)`$ begins.

The offsets are deterministic: $`s_0 = 0`$, and for $`i > 0`$:

```math
s_i = s_{i-1} + |\mathrm{encode\_frame}(F_{i-1})| + |\mathrm{right\_encode}(s_{i-1})|
```

### 5.1 Streaming Construction

The encoding can be constructed incrementally without knowing the length of any $`value_i`$ in advance:

1. Record the current transcript length as $`s_i`$.
2. Append $`op_i \mathbin\| \mathrm{encode\_string}(label_i)`$.
3. Stream $`value_i`$ into the transcript as data becomes available.
4. When the operation completes, append $`\mathrm{right\_encode}(s_i)`$.

No buffering or lookahead is required.

### 5.2 Overhead

Each frame incurs a position marker of $`|\mathrm{right\_encode}(s_i)|`$ bytes. For transcripts shorter than 256
bytes, each marker is 2 bytes. For transcripts shorter than 65536 bytes, each marker is 3 bytes. A typical
transcript instance (a few Mix operations before finalization) is well under 256 bytes, so the overhead is
approximately 2 bytes per frame.

## 6. Parse Algorithm

The following algorithm recovers the frame sequence from an encoded transcript by parsing position markers
right-to-left. All slice notation $`X[a \,..\, b]`$ denotes the half-open interval $`[a, b)`$: bytes at indices
$`a, a+1, \ldots, b-1`$.

```
Parse(T):
    frames ← []
    end ← |T|
    while end > 0:
        // Parse right_encode(s_i) from the right
        if end < 2: return ⊥                    // minimum right_encode is 2 bytes
        n ← T[end - 1]                          // last byte = length of integer encoding
        if n < 1: return ⊥                      // invalid length byte
        if n + 1 > end: return ⊥                // not enough bytes for right_encode
        s_i ← big_endian(T[end - 1 - n .. end - 1])
        marker_start ← end - 1 - n              // byte offset where right_encode(s_i) begins

        // Validate offset
        if s_i >= marker_start: return ⊥         // offset at or past the marker (no frame bytes)

        // Extract the frame bytes
        frame_bytes ← T[s_i .. marker_start]

        // Parse the frame: op || encode_string(label) || value
        if |frame_bytes| < 3: return ⊥           // minimum: 1 (op) + 2 (encode_string of empty)
        op ← frame_bytes[0]

        // Parse encode_string: left_encode(bit_len) || label
        n_l ← frame_bytes[1]                     // length-of-length byte for left_encode
        if n_l < 1: return ⊥
        if 2 + n_l > |frame_bytes|: return ⊥     // not enough bytes for left_encode
        bit_len ← big_endian(frame_bytes[2 .. 2 + n_l])
        if bit_len mod 8 ≠ 0: return ⊥           // bit-length must be a whole number of bytes
        byte_len ← bit_len / 8
        p ← 1 + 1 + n_l + byte_len               // cursor past encode_string
        if p > |frame_bytes|: return ⊥            // label extends past frame boundary
        label ← frame_bytes[1 + 1 + n_l .. 1 + 1 + n_l + byte_len]
        value ← frame_bytes[p ..]

        Prepend (op, label, value) to frames.

        // Advance to the preceding frame's region.
        // On valid encodings, the final iteration yields s_0 = 0, so end becomes 0
        // and the loop terminates. On invalid inputs where the last-parsed offset
        // is nonzero, the loop continues and will either reject or produce a
        // different frame sequence.
        end ← s_i
    return frames
```

### 6.1 Termination

Each iteration strictly reduces `end`. The offset validation $`s_i < \mathrm{marker\_start}`$ guarantees
$`s_i < \mathrm{end} - 2`$, so `end` decreases by at least 3 bytes per iteration on inputs that pass validation.
On inputs that fail validation, the algorithm returns $`\bot`$ immediately. The algorithm terminates in at most
$`\lfloor |T| / 3 \rfloor`$ iterations. Total work is $`O(|T|)`$.

### 6.2 Correctness on Valid Encodings

**Claim 1.** For any frame sequence $`F_0, \ldots, F_{m-1}`$, $`\mathrm{Parse}(\mathrm{encode\_transcript}(F_0, \ldots, F_{m-1}))`$
returns $`(F_0, \ldots, F_{m-1})`$.

*Proof.* **Base case ($`m = 0`$).** $`\mathrm{encode\_transcript}()`$ is the empty string. Parse receives $`|T| = 0`$,
the loop does not execute, and it returns $`[]`$. Correct.

**Base case ($`m = 1`$).** $`T = \mathrm{encode\_frame}(F_0) \mathbin\| \mathrm{right\_encode}(0)`$. The parser reads
$`\mathrm{right\_encode}(0)`$ from the right, obtaining $`s_0 = 0`$. The frame bytes are $`T[0 \,..\, \mathrm{marker\_start}]
= \mathrm{encode\_frame}(F_0)`$. Parsing the frame: the first byte is $`op_0`$; `encode_string` is self-delimiting,
so parsing from byte 1 recovers $`label_0`$ and advances the cursor to the start of $`value_0`$; the remaining
bytes are $`value_0`$. The parser sets $`\mathrm{end} \leftarrow 0`$ and returns $`[(op_0, label_0, value_0)]`$. Correct.

**Inductive step.** Suppose $`\mathrm{Parse}(\mathrm{encode\_transcript}(F_0, \ldots, F_{k-1})) = (F_0, \ldots, F_{k-1})`$
for all frame sequences of length $`k`$. Consider a valid encoding of $`k + 1`$ frames. By definition of `encode_transcript`, the encoded
transcript has the form:

```math
T = \underbrace{\mathrm{encode\_frame}(F_0) \mathbin\| \mathrm{right\_encode}(s_0) \mathbin\| \cdots \mathbin\| \mathrm{encode\_frame}(F_{k-1}) \mathbin\| \mathrm{right\_encode}(s_{k-1})}_{\mathrm{encode\_transcript}(F_0, \ldots, F_{k-1})} \mathbin\| \mathrm{encode\_frame}(F_k) \mathbin\| \mathrm{right\_encode}(s_k)
```

The parser reads $`\mathrm{right\_encode}(s_k)`$ from the right, obtains $`s_k`$, and extracts
$`\mathrm{encode\_frame}(F_k)`$ as the frame bytes between $`s_k`$ and $`\mathrm{marker\_start}`$. Since `encode_string`
is self-delimiting, parsing the frame correctly recovers $`(op_k, label_k, value_k)`$. The parser then sets
$`\mathrm{end} \leftarrow s_k`$. By the recurrence defining $`s_k`$ (§5), $`s_k = s_{k-1} + |\mathrm{encode\_frame}(F_{k-1})| + |\mathrm{right\_encode}(s_{k-1})|`$, so $`T[0 \,..\, s_k]`$ is exactly the prefix
$`\mathrm{encode\_transcript}(F_0, \ldots, F_{k-1})`$. Since Parse only accesses $`T[0 \,..\, \mathrm{end})`$ in each
iteration, its behavior from this point is identical to $`\mathrm{Parse}(T[0 \,..\, s_k])`$. By the inductive
hypothesis, the remaining iterations correctly recover $`F_0, \ldots, F_{k-1}`$. $`\square`$

## 7. Recoverability Proof

**Theorem 1.** `encode_transcript` is recoverable: it is injective, and there exists a polynomial-time
parser that recovers the frame sequence from any valid encoding.

*Proof.*

**Efficient decodability.** The Parse algorithm of §6 runs in $`O(|T|)`$ time on all inputs. On valid
encodings, it returns the original frame sequence (Claim 1). On invalid inputs, it returns $`\bot`$ at one of
the explicit validation checks. The algorithm terminates in polynomial time on all inputs because each
iteration either returns $`\bot`$ or consumes at least 3 bytes (§6.1).

**Injectivity.** Parse is a left inverse of `encode_transcript` (Claim 1): for all valid frame sequences $`F`$,
$`\mathrm{Parse}(\mathrm{encode\_transcript}(F)) = F`$. Any function with a left inverse is injective. $`\square`$

## 8. From KDF Inputs to Frames

The RO-KDF construction of BCFG25 operates on input tuples $`(\sigma_1, c_1), \ldots, (\sigma_n, c_n)`$ with a
label $`L`$ and output length $`\ell`$. To apply Theorem 8, the full pipeline from KDF inputs to hash function
input must be recoverable. This section defines the requirements for the mapping and proves recoverability
of the composition.

A protocol defines a **frame template**: a fixed, public mapping from the index set $`\{1, \ldots, n\}`$ to
frame-template sequences. For each index $`i`$, the template specifies the number of frames, their opcodes
and labels, and which fields carry $`\sigma_i`$ and $`c_i`$. The template is determined by the protocol
specification and is independent of the values $`(\sigma_i, c_i)`$. Frames are disambiguated by their ordinal
position in the sequence: two frames with identical (opcode, label) at different positions are distinct
because the template maps each position to a specific KDF input index.

**Claim 2.** If the frame template satisfies:

1. The template is a fixed, public function of the protocol structure: for each index $`i`$, the opcodes,
   labels, and the assignment of $`\sigma_i`$ and $`c_i`$ to frame fields are determined by $`i`$ and the protocol,
   not by the values $`(\sigma_i, c_i)`$ themselves.
2. Within each frame, the value field is a recoverable function of the input it carries: there exists a
   polynomial-time algorithm that recovers the input from the value field. (In the common case where the
   input is placed directly in the value field — the identity function — recoverability is trivial.)
3. The label $`L`$ is encoded as a domain separation parameter to H (see §9).

Then:

(a) Distinct KDF input tuples $`((\sigma_1, c_1), \ldots, (\sigma_n, c_n))`$ at fixed $`L`$ produce distinct frame
sequences.

(b) The composed encoding from KDF inputs to byte strings is recoverable: given the byte string, the
simulator can recover the KDF-level inputs by first applying Parse (§6) to recover the frame sequence, then
applying the publicly known template inverse to extract $`(\sigma_i, c_i)`$ from the frame fields. Both steps
are polynomial-time.

*Proof.* **(a)** If two input tuples differ in $`(\sigma_i, c_i)`$ for some $`i`$, then by condition (1) they produce
frame sequences that differ in the frame(s) assigned to index $`i`$, and by condition (2) the differing input
produces a different value field (recoverability implies injectivity). If the tuples have different lengths
($`n \neq n'`$), the frame sequences have different lengths and are trivially distinct.

**(b)** Parse recovers the frame sequence in $`O(|T|)`$ time (Theorem 1). The template inverse is a fixed,
public function that maps each frame's position and opcode/label to the corresponding $`(\sigma_i, c_i)`$
extraction rule. By condition (2), the extraction from each value field is polynomial-time. Since the
template is independent of the values, the composed inverse is well-defined and efficient. $`\square`$

## 9. Hash Function Requirements

Let H be a hash function mapping arbitrary-length byte strings to variable-length outputs (XOF). We
require:

1. **Indifferentiability from a random oracle.** There exists a simulator $`\mathcal{S}`$ such that no efficient
   adversary can distinguish $`(\mathrm{H}, \pi)`$ from $`(\mathrm{RO}, \mathcal{S}^{\mathrm{RO}})`$ with advantage better than
   $`\varepsilon_{\mathrm{indiff}}`$, where RO is a random oracle with the same domain and range and $`\pi`$ is the
   ideal permutation underlying H.

2. **Domain separation.** H accepts a domain separation parameter $`S`$ such that evaluations with distinct
   values of $`S`$ are modeled as independent random oracles. Formally: for $`S_1 \neq S_2`$, the functions
   $`M \mapsto H(M, S_1, \ell)`$ and $`M \mapsto H(M, S_2, \ell)`$ are independent. This requires that the
   internal encoding of $`(M, S)`$ is injective — distinct $`(M, S)`$ pairs must produce distinct inputs to the
   underlying primitive — and that the input spaces for distinct $`S`$ values are disjoint.

Under these assumptions, the RO-KDF construction $`K \leftarrow H(\mathrm{encode\_transcript}(\ldots), S, \ell)`$
satisfies Theorem 8 of BCFG25 for each choice of $`S`$ independently.

The label $`L`$ of the $`n`$-KDF (BCFG25, Definition 7) maps directly to the domain separation parameter $`S`$
of H: $`S = L`$. Since distinct $`S`$ values select independent random oracles, the recoverability requirement
applies only to the transcript encoding within each oracle, which is satisfied by Theorem 1 and Claim 2.

The per-oracle KDF advantage for a KDF with $`r`$ key material sources is bounded by:

```math
\mathrm{Adv}^{\mathrm{kdf}} \leq \varepsilon_{\mathrm{indiff}} + 2 \cdot \sum_{i=1}^{r} \mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}(\mathcal{B}_i)
```

The first term accounts for replacing H with a random oracle; the second is the RO-KDF bound from
Theorem 8, where $`\mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}`$ is the source unpredictability advantage — the maximum
probability that any efficient adversary, given access to a prediction oracle, correctly guesses the output
of source $`\Sigma_i`$. The reduction relies on the recoverability of the composed encoding (§7, §8) to
construct the simulator $`\mathcal{B}_i`$ that extracts target secrets from random oracle queries.

## 10. Instantiation with KT128

KangarooTwelve (KT128), specified in RFC 9861, satisfies the requirements of §9.

### 10.1 Indifferentiability

KT128 is built on TurboSHAKE128 using Sakura encoding for tree hashing. Sakura (Bertoni, Daemen, Peeters, Van Assche, 2013)
defines a coding convention for tree hash modes and proves that any tree hash mode using Sakura coding is
as strong as the underlying hash function: the distinguishing advantage of the tree hash from a random
oracle, given the inner function is ideal, is at most $`q_{\mathrm{tree}}^2 / 2^{c+1}`$, where
$`q_{\mathrm{tree}}`$ is the number of inner function calls and $`c`$ is the capacity of the underlying sponge. KT128 is a concrete application of Sakura
(Bertoni, Daemen, Peeters, Van Assche, Van Keer, Viguier, 2016). The inner function is TurboSHAKE128, which is indifferentiable from a random oracle
under the ideal permutation model for Keccak-p[1600,12] (Bertoni, Daemen, Peeters, Van Assche, 2008) with advantage
$`(\sigma + t)^2 / 2^{c+1}`$, where $`c = 256`$ is the capacity, $`\sigma`$ is the total number of online
Keccak-p calls, and $`t`$ is the adversary's offline budget.

By the indifferentiability composition theorem (Maurer, Renner, Holenstein, 2004) — with Sakura tree
hashing as the outer construction and TurboSHAKE128 as the inner primitive — the combined
indifferentiability advantage of KT128 from a random oracle is at most:

```math
\varepsilon_{\mathrm{indiff}} \leq \frac{q_{\mathrm{tree}}^2}{2^{c+1}} + \frac{(\sigma + t)^2}{2^{c+1}}
```

where $`\sigma`$ counts the online Keccak-p calls across all TurboSHAKE128 evaluations. Since each
inner-function call involves at least one Keccak-p call, $`q_{\mathrm{tree}} \leq \sigma`$, so this
simplifies to $`\varepsilon_{\mathrm{indiff}} \leq 2(\sigma + t)^2 / 2^{c+1}`$. With $`c = 256`$, the
128-bit security level is maintained.

### 10.2 Domain Separation

KT128 accepts a customization string $`S`$. Internally, KT128 appends
$`S \mathbin\| \mathrm{right\_encode}(|S|)`$ after the message (RFC 9861, §3.2; `right_encode` here encodes the
byte length of $`S`$, following the RFC convention). This encoding is injective: given the final-node input,
$`|S|`$ can be recovered by parsing $`\mathrm{right\_encode}`$ from the right, then extracting $`|S|`$ bytes before it to
obtain $`S`$. Consequently, the input spaces for distinct customization strings are disjoint, and evaluations
with distinct $`S`$ values are modeled as independent random oracles.

### 10.3 Instantiation

The transcript-based KDF is instantiated as:

```math
K \leftarrow \mathrm{KT128}(\mathrm{encode\_transcript}(F_0, \ldots, F_{m-1}),\; S,\; \ell)
```

where $`S`$ is a customization string providing domain separation and $`\ell`$ is the output length in bytes.

### 10.4 Combined Bound

We assume each key material source $`\Sigma_i`$ has $`\kappa`$ bits of min-entropy. The adversary
$`\mathcal{B}_i`$ receives a sample from $`\Sigma_i`$ and must predict it using a prediction oracle that
confirms or denies each guess. Each guess succeeds with probability at most $`2^{-\kappa}`$ (by the
min-entropy bound), so over $`t`$ queries:
$`\mathrm{Adv}^{\mathrm{up}}_{\Sigma_i}(\mathcal{B}) \leq t / 2^{\kappa}`$.

For a single KDF instance with $`r`$ key material sources:

```math
\mathrm{Adv}^{\mathrm{kdf}} \leq \frac{2(\sigma + t)^2}{2^{257}} + 2 \cdot r \cdot \frac{t}{2^{\kappa}}
```

For a protocol with $`q`$ independent KDF instances (e.g., $`q`$ finalizing operations, each beginning a new
transcript via a chain value), the multi-instance bound is obtained by union bound:

```math
\mathrm{Adv}^{\mathrm{kdf}}_{\mathrm{total}} \leq \frac{2(\sigma + t)^2}{2^{257}} + 2 \cdot q \cdot r \cdot \frac{t}{2^{\kappa}}
```

The indifferentiability term is not multiplied by $`q`$ because it is a global property of the permutation shared
across all instances.

This bound requires that each transcript instance contains at least one source with $`\kappa`$ bits of
min-entropy independent of the chain value. Composition across chain boundaries — where the chain value
from one KDF instance provides pseudorandom input to the next — requires a protocol-level argument that
(1) the chain value carries sufficient min-entropy into the next instance, and (2) the chain value is
independent of any fresh key material in the next instance. This argument is outside the scope of this
document and must be established by the instantiating protocol.

## References

- Backendal, M., Clermont, S., Fischlin, M., and Günther, F. "Key Derivation Functions Without a Grain
  of Salt." Eurocrypt 2025 / IACR ePrint 2025/657.
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
- NIST SP 800-185: SHA-3 Derived Functions. Defines `left_encode`, `right_encode`, and `encode_string`.
- RFC 9861: KangarooTwelve and TurboSHAKE. Specifies KT128.
