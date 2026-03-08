package thyrse_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/thyrse"
)

// TestVectors verifies the reference implementation against the test vectors in §16 of
// docs/protocol-spec.md.

func TestVectors(t *testing.T) {
	t.Run("InitDerive", func(t *testing.T) {
		// §16.1: Init + Derive — minimal protocol producing output.
		p := thyrse.New("test.vector")
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), "25feba088971a4b573101369ea1c8d83e6f102c2dc46e5cceb81a0b97fca514c"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MixMixDerive", func(t *testing.T) {
		// §16.2: Init + Mix + Mix + Derive — multiple non-finalizing operations.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), "0db4090efec2ba935dac63a18d88df04859d1dedf4a60f428393674520b67e39"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealDerive", func(t *testing.T) {
		// §16.3: Init + Mix + Seal + Derive — full AEAD followed by Derive.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		seal := p.Seal("message", nil, []byte("hello, world!"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(seal), "dde795eebaaa663b55e904c1e4da1c6c6f1c770b9c90fd17b8add38741dd5e4c821ad0e5aeb4bbfbc18d89ebe4"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "e6a99cd5ac77af8370dd09e5f1ea020b1ded0a7415a9dadcbe6133e917dd2498"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "21fc87f3008b3cff62fb2584c970"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "f078ea89c7dea34a821c8470544ec5a70061c75aa9de8a1d49e4a9e816455ca54f78e50a2a1981d1c0a47cfe4d20"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
	})

	t.Run("RatchetDerive", func(t *testing.T) {
		// §16.5: Init + Mix + Ratchet + Derive — forward secrecy.

		// Without Ratchet.
		p1 := thyrse.New("test.vector")
		p1.Mix("key", []byte("test-key-material"))
		derive1 := p1.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive1), "b20333efd472bf1cafbdfcc7c4aef46ca9984b768dbf84e33006024bead07dcf"; got != want {
			t.Errorf("Derive (no Ratchet) = %s, want = %s", got, want)
		}

		// With Ratchet.
		p2 := thyrse.New("test.vector")
		p2.Mix("key", []byte("test-key-material"))
		p2.Ratchet("forward-secrecy")
		derive2 := p2.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive2), "23be92e694890a8b3d6fb5b4885b3b5a63539ad8da6fc5e8e20cf34728dbeb91"; got != want {
			t.Errorf("Derive (after Ratchet) = %s, want = %s", got, want)
		}
	})

	t.Run("ForkDerive", func(t *testing.T) {
		// §16.6: Fork + Derive — independent outputs from three branches.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		left, right := p.Fork("role", []byte("prover"), []byte("verifier"))
		base := p.Derive("output", nil, 32)
		leftDerive := left.Derive("output", nil, 32)
		rightDerive := right.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(base), "53fa58633361a67384c7a6d8df0e6163dac581024e9786856442edf13e5b787c"; got != want {
			t.Errorf("Base Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(leftDerive), "329696ce84ae7aef8577db9841d82956b60f9f7ce38449d8b83092f3a46a89ad"; got != want {
			t.Errorf("Prover Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(rightDerive), "19644cc5d0a5bc8f52eb647a581b85ba868ce0cb3561f8d2a58f1bf6ed1a3e82"; got != want {
			t.Errorf("Verifier Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealOpenRoundTrip", func(t *testing.T) {
		// §16.8: Seal + Open round-trip — successful authenticated encryption and decryption.
		key := []byte("test-key-material")
		nonce := []byte("test-nonce-value")
		ad := []byte("associated data")
		plaintext := []byte("hello, world!")

		// Seal side.
		pSeal := thyrse.New("test.vector")
		pSeal.Mix("key", key)
		pSeal.Mix("nonce", nonce)
		pSeal.Mix("ad", ad)
		sealed := pSeal.Seal("message", nil, plaintext)
		sealDerive := pSeal.Derive("confirm", nil, 32)

		// Open side.
		pOpen := thyrse.New("test.vector")
		pOpen.Mix("key", key)
		pOpen.Mix("nonce", nonce)
		pOpen.Mix("ad", ad)
		opened, err := pOpen.Open("message", nil, sealed)
		if err != nil {
			t.Fatal(err)
		}
		openDerive := pOpen.Derive("confirm", nil, 32)

		if got, want := hex.EncodeToString(sealed), "1383ffe1d63304655b9b94ae27f2a50ea1734e2df148381c2080d70ad86bac40e84d08e43b48b0b9f4a106156a"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if !bytes.Equal(sealDerive, openDerive) {
			t.Errorf("Seal-side and Open-side Derive diverge:\n  seal = %s\n  open = %s",
				hex.EncodeToString(sealDerive), hex.EncodeToString(openDerive))
		}
	})

	t.Run("SealOpenTampered", func(t *testing.T) {
		// §16.9: Seal + Open with tampered ciphertext — authentication fails, transcripts desynchronize.
		key := []byte("test-key-material")
		nonce := []byte("test-nonce-value")
		plaintext := []byte("hello, world!")

		// Seal side.
		pSeal := thyrse.New("test.vector")
		pSeal.Mix("key", key)
		pSeal.Mix("nonce", nonce)
		sealed := pSeal.Seal("message", nil, plaintext)
		sealDerive := pSeal.Derive("after", nil, 32)

		if got, want := hex.EncodeToString(sealed), "6e73c8fb8e615ac7d3bfdeaaa7e8e1af189b97db42b2870b693c5faf0be6bbc8345d8830401a53acccc756500a"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		// Tamper with ciphertext (flip first byte).
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0xff

		// Open side with tampered data.
		pOpen := thyrse.New("test.vector")
		pOpen.Mix("key", key)
		pOpen.Mix("nonce", nonce)
		_, err := pOpen.Open("message", nil, tampered)
		if err == nil {
			t.Fatal("Open must reject tampered ciphertext")
		}
		openDerive := pOpen.Derive("after", nil, 32)

		if bytes.Equal(sealDerive, openDerive) {
			t.Error("seal and open Derive should differ after tampered ciphertext")
		}
	})

	t.Run("MultipleSeals", func(t *testing.T) {
		// §16.10: Multiple Seals in sequence — each key differs via tag absorption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		seal1 := p.Seal("msg", nil, []byte("first message"))
		seal2 := p.Seal("msg", nil, []byte("second message"))
		seal3 := p.Seal("msg", nil, []byte("third message"))

		if got, want := hex.EncodeToString(seal1), "f58f5895735ec5679a75651160f0e2b29ea495e5a13e482d22c5bd1f58c75a345a9dacbf4205022b27f809fcc2"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "2b6b64822aa4ac6716aaf6226e20d4d9f1c6ac6bafbe00761b03663b3e574d91be5fa8918945fa311214cfa83e1b"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "86de20dad1084ed184d23aa56a3c3001a468b67c6687b2ab93e5b640008b6c912f88b6a3a88cd4283a7719c273"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
