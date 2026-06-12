# Thyrse

![A diagram of a botanical thyrse.](thyrse.png)

> [!WARNING]
> **This code has not been audited. This design has not been analyzed.** It is experimental and should not be used for
> production systems or critical security applications. Use at your own risk.

Thyrse is a transcript-based cryptographic protocol framework built on the KT128 hash function, AES-128-CTR encryption,
and AES-128-GMAC authentication.
Inspired by [STROBE], [Noise Protocol], and [Xoodyak], it replaces the usual grab-bag of hash functions, MACs, and KDFs
with a single construction.  Optimized for modern CPUs (AVX-512, NEON/FEAT_SHA3, hardware AES), Thyrse
delivers 10+ Gb/s on modern processors at a 128-bit security level.

The security of every scheme reduces to the properties of the underlying hash function (indifferentiability from a random
oracle, pseudorandom function security, and collision resistance) and the AES-128-CTR encryption and AES-128-GMAC
authentication, all at a
128-bit security level ($2^{128}$ against generic attacks). A single analysis covers the framework's transcript layer.

[STROBE]: https://strobe.sourceforge.io

[Noise Protocol]: http://www.noiseprotocol.org

[Xoodyak]: https://keccak.team/xoodyak.html

## Schemes

Thyrse ships with a library of ready-to-use cryptographic schemes built on the core `Protocol` type.

### Basic

| Scheme       | What it does                                                               |
|--------------|----------------------------------------------------------------------------|
| **digest**   | Hash (32 bytes) and HMAC (16 bytes) via `New` / `NewKeyed`                 |
| **aead**     | Authenticated encryption implementing `crypto/cipher.AEAD`                 |
| **siv**      | Nonce-misuse-resistant AEAD (Synthetic Initialization Vector)              |
| **aestream** | Streaming authenticated encryption with `io.Reader` / `io.Writer` wrappers |
| **oae2**     | Online authenticated encryption with block-based streaming                 |
| **mhf**      | Data-dependent memory-hard function (DEGSample, Blocki & Holman 2025)      |

### Complex

| Scheme        | What it does                                                                 |
|---------------|------------------------------------------------------------------------------|
| **sig**       | EdDSA-style Schnorr signatures over Ristretto255                             |
| **hpke**      | Hybrid public-key encryption (static-ephemeral DH)                           |
| **signcrypt** | Signcryption — confidentiality, authenticity, and signer privacy in one shot |
| **oprf**      | Oblivious pseudorandom function with blinding (RFC 9497-style)               |
| **vrf**       | Verifiable random function with proofs                                       |
| **pake**      | Password-authenticated key exchange (CPace-style)                            |
| **frost**     | FROST threshold signatures (Flexible Round-Optimized Schnorr Threshold)      |
| **adratchet** | Asynchronous double ratchet with forward secrecy and break-in recovery       |

All schemes are in `schemes/basic/` and `schemes/complex/` respectively.

## Performance

Under the hood, Thyrse hashes inputs and derives keys with [KT128], a tree-parallel, permutation-based construction that
uses SIMD instructions for lower latency on short inputs and higher throughput on long ones.

| Platform | SIMD             | Parallel lanes        |
|----------|------------------|-----------------------|
| x86-64   | AVX-512 / AVX2   | 8-wide                |
| ARM64    | NEON / FEAT_SHA3 | up to 4-wide          |
| Any      | Pure Go          | all widths (portable) |

Encryption uses AES-128-CTR with an AES-128-GMAC tag over the ciphertext, computed in a single pass via the stitched
AES-CTR + GHASH assembly from the Go standard library — AES-NI and
PCLMULQDQ on x86-64, ARMv8 AES and PMULL on ARM64 — with a constant-time portable fallback elsewhere.

Build with `-tags purego` to disable assembly on any platform.

[KT128]: https://github.com/codahale/kt128

## The Protocol API

At the core is a `Protocol` — a transcript that accumulates data and derives cryptographic outputs.

```go
p := thyrse.New("myapp.v1")
p.Mix("user-id", userID)
p.Mix("nonce", nonce)
ct := p.Seal("message", nil, plaintext) // encrypt + authenticate
```

Key operations: `Mix`, `Derive`, `Ratchet`, `Mask`/`Unmask`, `Seal`/`Open`, `Fork`/`ForkN`, `Clone`, `Clear`.

## License

MIT or Apache 2.0.
