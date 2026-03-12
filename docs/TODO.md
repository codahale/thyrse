# TODO

- [ ] Revisit H=64 (512-bit chain values): 256-bit (H=32) is sufficient for 128-bit security at q=2^48, matches C, simplifies parameters. Margin thins at multi-user scale (2^-129 at U·q=2^64).
- [ ] Analyze the async dual ratchet example scheme via the ACD19 (Alwen, Coretti, Dodis) framework: CKA + FS-AEAD + PRF-PRNG composition.