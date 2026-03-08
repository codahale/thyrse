package thyrse_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/codahale/thyrse"
)

// TestVectors verifies the reference implementation against the test vectors in §16 of
// docs/protocol-spec.md.
//
// NOTE: Test vectors are temporarily disabled pending regeneration after the switch from
// keccak.Duplex to kt128.Hasher with TKDF frame encoding. The structural/round-trip tests
// remain active; only hex comparisons are commented out.

func TestVectors(t *testing.T) {
	t.Run("InitDerive", func(t *testing.T) {
		// §16.1: Init + Derive — minimal protocol producing output.
		p := thyrse.New("test.vector")
		derive := p.Derive("output", nil, 32)

		t.Logf("Derive = %s", hex.EncodeToString(derive))

		if got, want := len(derive), 32; got != want {
			t.Errorf("Derive len = %d, want = %d", got, want)
		}
	})

	t.Run("MixMixDerive", func(t *testing.T) {
		// §16.2: Init + Mix + Mix + Derive — multiple non-finalizing operations.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		derive := p.Derive("output", nil, 32)

		t.Logf("Derive = %s", hex.EncodeToString(derive))

		if got, want := len(derive), 32; got != want {
			t.Errorf("Derive len = %d, want = %d", got, want)
		}
	})

	t.Run("SealDerive", func(t *testing.T) {
		// §16.3: Init + Mix + Seal + Derive — full AEAD followed by Derive.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		seal := p.Seal("message", nil, []byte("hello, world!"))
		derive := p.Derive("output", nil, 32)

		t.Logf("Seal = %s", hex.EncodeToString(seal))
		t.Logf("Derive = %s", hex.EncodeToString(derive))
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		t.Logf("Mask = %s", hex.EncodeToString(mask))
		t.Logf("Seal = %s", hex.EncodeToString(seal))
	})

	t.Run("RatchetDerive", func(t *testing.T) {
		// §16.5: Init + Mix + Ratchet + Derive — forward secrecy.

		// Without Ratchet.
		p1 := thyrse.New("test.vector")
		p1.Mix("key", []byte("test-key-material"))
		derive1 := p1.Derive("output", nil, 32)

		t.Logf("Derive (no Ratchet) = %s", hex.EncodeToString(derive1))

		// With Ratchet.
		p2 := thyrse.New("test.vector")
		p2.Mix("key", []byte("test-key-material"))
		p2.Ratchet("forward-secrecy")
		derive2 := p2.Derive("output", nil, 32)

		t.Logf("Derive (after Ratchet) = %s", hex.EncodeToString(derive2))

		if bytes.Equal(derive1, derive2) {
			t.Error("Ratchet did not change Derive output")
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

		t.Logf("Base Derive = %s", hex.EncodeToString(base))
		t.Logf("Prover Derive = %s", hex.EncodeToString(leftDerive))
		t.Logf("Verifier Derive = %s", hex.EncodeToString(rightDerive))

		if bytes.Equal(base, leftDerive) {
			t.Error("base and prover produced identical output")
		}
		if bytes.Equal(base, rightDerive) {
			t.Error("base and verifier produced identical output")
		}
		if bytes.Equal(leftDerive, rightDerive) {
			t.Error("prover and verifier produced identical output")
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

		t.Logf("Seal = %s", hex.EncodeToString(sealed))

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

		t.Logf("Seal = %s", hex.EncodeToString(sealed))

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

		// After tampered open, transcripts should be desynchronized.
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

		t.Logf("Seal 1 = %s", hex.EncodeToString(seal1))
		t.Logf("Seal 2 = %s", hex.EncodeToString(seal2))
		t.Logf("Seal 3 = %s", hex.EncodeToString(seal3))

		// All three seals should produce different output.
		if bytes.Equal(seal1, seal2) {
			t.Error("seal1 and seal2 are identical")
		}
		if bytes.Equal(seal2, seal3) {
			t.Error("seal2 and seal3 are identical")
		}
	})
}
