# TODO

- [ ] Revisit H=64 (512-bit chain values): 256-bit (H=32) is sufficient for 128-bit security at q=2^48, matches C, simplifies parameters. Margin thins at multi-user scale (2^-129 at U·q=2^64).
- [ ] Clean up `import hmac as _hmac` in ref/thyrse.py — no reason for the underscore prefix, just use `hmac.compare_digest` directly.
- [ ] Analyze the async dual ratchet example scheme via the ACD19 (Alwen, Coretti, Dodis) framework: CKA + FS-AEAD + PRF-PRNG composition.
- [ ] Add test vectors for TreeWrap edge cases: R+1 (169) bytes, B-1 (8191) bytes, high chunk count (n ≥ 256), multi-block KDF absorption (long AD/nonce exceeding one rate block)