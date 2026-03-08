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

		if got, want := hex.EncodeToString(derive), "ec87c46ba1e15dd2d3dd8d65a921d580b0def8e211d221c714a852db5db335e7"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MixMixDerive", func(t *testing.T) {
		// §16.2: Init + Mix + Mix + Derive — multiple non-finalizing operations.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), "fa88a380fe5f1787388a416bbadb197da65c35ce4a2bffaac27c66ce70afa712"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealDerive", func(t *testing.T) {
		// §16.3: Init + Mix + Seal + Derive — full AEAD followed by Derive.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		seal := p.Seal("message", nil, []byte("hello, world!"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(seal), "dbd96564e96622fc54d40059c68c3bbe5125092687fc71be922b897acfec6ee6ae0018b267ae8d0d5ad3f25086"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "7cc83addda8780f79f6bd4d21ea77533fe6c4cd89fe15992832d7359af7b02c8"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "311267c1afd96b79a81dd1c660d2"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "b1085cd21292abe9f4f0ccc3ba70f0cf0fcf58c2750bd2711e4fb7c14ba6581199385983f147cd0b3581ec168112"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
	})

	t.Run("RatchetDerive", func(t *testing.T) {
		// §16.5: Init + Mix + Ratchet + Derive — forward secrecy.

		// Without Ratchet.
		p1 := thyrse.New("test.vector")
		p1.Mix("key", []byte("test-key-material"))
		derive1 := p1.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive1), "aa3a86f09a0dba52914a1fba6c316363c3adef98fc5c4ff7008295b090b69193"; got != want {
			t.Errorf("Derive (no Ratchet) = %s, want = %s", got, want)
		}

		// With Ratchet.
		p2 := thyrse.New("test.vector")
		p2.Mix("key", []byte("test-key-material"))
		p2.Ratchet("forward-secrecy")
		derive2 := p2.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive2), "d7b13566eeb12ba72734d09c91eadf85abd5097aed275df6ac5f93bcdb70f937"; got != want {
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

		if got, want := hex.EncodeToString(base), "3555f825df4548a124b0a7c3b9ea6d6eb7c9520a2d0e65fbf18b126df370f942"; got != want {
			t.Errorf("Base Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(leftDerive), "cdd9a0d4e77f028d062fb08cc358c33114433165fec081f4fd9d3a5248522917"; got != want {
			t.Errorf("Prover Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(rightDerive), "4b6ce702e0e221bdb977267f6cea87b801ea94f463e733b6abbc115ae89782b4"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "b903f8dc5c06b1dfa4d21954a1a76b434bdea9a52f55de1141ee9ab14c00f4620c442a9e1d43494ed9ea4a5a31"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if got, want := hex.EncodeToString(sealDerive), "355b1fc37f31822bfc15e48f5180d98918d9e11afef68af0483d623a6252c0af"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "355b1fc37f31822bfc15e48f5180d98918d9e11afef68af0483d623a6252c0af"; got != want {
			t.Errorf("Open-side Derive = %s, want = %s", got, want)
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

		if got, want := hex.EncodeToString(sealed), "b384534abc97b003db373f37acb990390102c05cd8d8c1ee9836eea750e36ce655422f140c0fcfde1ec71ff198"; got != want {
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

		if got, want := hex.EncodeToString(sealDerive), "4b1c9a8425832683ea75835e12fa29f9edd37104fde2b9ee1d3475422fc69765"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "b80e22c2fe18df1a88fd721d36b9503d5167d0f479131210bb83e0d0b773c5f8"; got != want {
			t.Errorf("Open-side Derive (desynchronized) = %s, want = %s", got, want)
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

		if got, want := hex.EncodeToString(seal1), "998adcc734cdb43a7c89f44435c8eb1f1084d1957e4c06991d6f0d66c25eb0907fc8753695ef121d2fec419cac"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "0add0cbf66dbc86d309ebf0abdc0339ae9cb4a026cd79ecd22c7fc7f1ce1bddca2d187541aa725d4c32e5c6df5a8"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "590197f8dcd1725160c017038f89789c6f8c9a018982b96666f5eafd112bb2adc35a35ef07077fe2c8fdc16348"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
