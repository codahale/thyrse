# Thyrse

![A diagram of a botanical thyrse.](thyrse.png)

> [!WARNING]
> Thyrse is experimental. Neither the design nor the implementation has been independently analyzed or audited. Do not
> use it in production systems or for critical security applications.
>
> Thyrse depends on [github.com/codahale/kt128](https://github.com/codahale/kt128) for KT128 and
> [github.com/gtank/ristretto255](https://github.com/gtank/ristretto255) for the group operations used by
> `schemes/complex`. The latter is lightly maintained.

Thyrse is a Go framework for transcript-based cryptographic protocols. A `Protocol` records labeled operations in a
KT128 transcript and derives per-operation keys, tags, and pseudorandom output from the accumulated state. Encryption
uses AES-128-CTR. The construction targets a 128-bit security level.

On supported modern processors, core operations reach 10+ Gb/sec using SIMD implementations of KT128 and hardware AES.
Actual throughput depends on the operation, message size, processor, and Go version.

Thyrse is influenced by [STROBE], the [Noise Protocol], and [Xoodyak].

[STROBE]: https://strobe.sourceforge.io
[Noise Protocol]: http://www.noiseprotocol.org
[Xoodyak]: https://keccak.team/xoodyak.html

## Security model

Confidentiality and authenticity require secret input with sufficient entropy to be mixed into the transcript. Public
nonces, labels, and associated data provide domain separation and context, but do not key the protocol.

`Mask` and `MaskStream` provide unauthenticated AES-128-CTR encryption. They absorb the ciphertext into the transcript,
but callers must provide authentication separately. `Seal` encrypts the plaintext, absorbs the ciphertext, and derives
an authentication tag from the resulting keyed transcript. `Open` verifies that tag before returning plaintext.

Operations are encoded with their labels, types, and variable-length field boundaries. Finalizing operations replace
the accumulated transcript with a derived chain value, so later operations depend on the complete prior transcript.

On platforms without hardware AES support, Go uses a software AES implementation that is not constant-time. `Mask`,
`Unmask`, `MaskStream`, `UnmaskStream`, `Seal`, and `Open` can therefore leak timing information about their
per-operation keys on those platforms.

## Schemes

The repository includes schemes built on the core `Protocol` type.

### Basic

| Package    | Function                                                        |
|------------|-----------------------------------------------------------------|
| `digest`   | 32-byte hashes and 16-byte keyed digests                        |
| `aead`     | Authenticated encryption implementing `crypto/cipher.AEAD`      |
| `siv`      | Nonce-misuse-resistant authenticated encryption                 |
| `aestream` | Streaming authenticated encryption over `io.Reader`/`io.Writer` |
| `oae2`     | Block-based online authenticated encryption                     |
| `mhf`      | Balloon-based memory-hard password hashing                      |

### Complex

| Package     | Function                                                      |
|-------------|---------------------------------------------------------------|
| `sig`       | Schnorr signatures over Ristretto255                          |
| `hpke`      | Static-ephemeral public-key encryption                        |
| `signcrypt` | Signcryption with sender privacy                              |
| `oprf`      | Blinded pseudorandom function evaluation with proofs          |
| `vrf`       | Verifiable pseudorandom function                              |
| `pake`      | Password-authenticated key exchange                           |
| `frost`     | Threshold Schnorr signatures                                  |
| `adratchet` | Asynchronous double ratchet using X25519 and ML-KEM-768      |

The packages are under `schemes/basic` and `schemes/complex`.

## Performance

[KT128] is tree-parallel and uses architecture-specific SIMD where available. Encryption uses AES-128-CTR from Go's
standard library, including AES-NI on x86-64 and ARMv8 AES instructions on ARM64. Large one-shot encryption operations
interleave encryption and transcript absorption over bounded windows. The streaming APIs process data incrementally
and do not retain the complete input.

| Platform | KT128 implementation | AES implementation           |
|----------|----------------------|------------------------------|
| x86-64   | AVX-512 or AVX2      | AES-NI when available        |
| ARM64    | NEON or FEAT_SHA3    | ARMv8 AES when available     |
| Other    | Pure Go              | Go standard library fallback |

Build with `-tags purego` to disable assembly implementations.

[KT128]: https://github.com/codahale/kt128

## Protocol API

A protocol begins with a domain-separation label:

```go
p := thyrse.New("myapp.v1")
p.Mix("user-id", userID)
p.Mix("nonce", nonce)
sealed := p.Seal("message", nil, plaintext)
```

| Operation                     | Function                                                         |
|-------------------------------|------------------------------------------------------------------|
| `Mix`, `MixWriter`            | Absorb public or secret input                                    |
| `Derive`                      | Produce deterministic pseudorandom output                        |
| `Ratchet`                     | Advance the state without producing output                       |
| `Mask`, `Unmask`              | Encrypt or decrypt without authentication                        |
| `MaskStream`, `UnmaskStream`  | Stream unauthenticated encryption or decryption                  |
| `Seal`, `Open`                | Authenticated encryption or decryption                           |
| `Fork`, `ForkN`               | Split the state into independent branches                        |
| `Clone`                       | Copy the current state without one-way separation                |
| `Clear`                       | Erase and invalidate the protocol state                          |

Writers and streams must be closed to complete their transcript operation. The associated `Protocol` must not be used
for another operation until they are closed.

## License

MIT or Apache 2.0.
