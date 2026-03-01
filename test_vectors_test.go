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

		if got, want := hex.EncodeToString(derive), "91a9244784060174970bbbe8395f7f7e4d055c16be368594c0707413dcdfcc58"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MixMixDerive", func(t *testing.T) {
		// §16.2: Init + Mix + Mix + Derive — multiple non-finalizing operations.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), "fcac8c24985876bdd4e034552fdbeedca786fb7689a196a3acaf643f1c1c2a6a"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealDerive", func(t *testing.T) {
		// §16.3: Init + Mix + Seal + Derive — full AEAD followed by Derive.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		seal := p.Seal("message", nil, []byte("hello, world!"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(seal), "645c4ee5330811bf8f8a2070651ea3c503c78d7ef8f2c03fce2f7f2493a95fd299c4743a56048c4b8beccf2eeb"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "3d0207b0f8e5238cadfb589172fffe8059827243b0b602c27f2cb2814031879b"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "260ea77cc6b8ee60b060cac87e6f"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "d3d859139486f7f39dd9228fac735abf9b1719ab161559cc834993b17296f801389aabdfcc52c659fcb2feeb48cb"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
	})

	t.Run("RatchetDerive", func(t *testing.T) {
		// §16.5: Init + Mix + Ratchet + Derive — forward secrecy.

		// Without Ratchet.
		p1 := thyrse.New("test.vector")
		p1.Mix("key", []byte("test-key-material"))
		derive1 := p1.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive1), "7533c628ab03a2be92718588568284f73f467a54f173d8aaa2035ae3d2672945"; got != want {
			t.Errorf("Derive (no Ratchet) = %s, want = %s", got, want)
		}

		// With Ratchet.
		p2 := thyrse.New("test.vector")
		p2.Mix("key", []byte("test-key-material"))
		p2.Ratchet("forward-secrecy")
		derive2 := p2.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive2), "e1af44127866b8588c68e10f17ff7d1d37f12a4e3526a69d8cb220f241fefd31"; got != want {
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

		if got, want := hex.EncodeToString(base), "b5b07c94401b4d6e6b9a9289c1ad858327822f7cbe1e459e8d58ccc5b5f40b5d"; got != want {
			t.Errorf("Base Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(leftDerive), "ab999f91045ddeb4b743a03c9256b9fd7a913e1ebb3fcd28bed9680534292d63"; got != want {
			t.Errorf("Prover Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(rightDerive), "09236bba933c0d9937c93d2bc8ac77f65a87b380a88ad34ffec206e76892c0eb"; got != want {
			t.Errorf("Verifier Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MixStream", func(t *testing.T) {
		// §16.7: MixStream — pre-hash of a 10000-byte input via KT128.
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 251)
		}

		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		if err := p.MixStream("stream-data", bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), "7e7a81e3d8c4dd701883430697e1aa956b0ad990a1b0823bc3eaca1f9078d768"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
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

		if got, want := hex.EncodeToString(sealed), "667911010907507537fa5ab3a8345d769cbc1167e26edaaa4a38f38a6430f09be3b7917b1ec1f30d667c811612"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if got, want := hex.EncodeToString(sealDerive), "1cf32253d292ddb3c3b5ccca4c20daa63f45da40cc47b4598c9643b347035bb9"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "1cf32253d292ddb3c3b5ccca4c20daa63f45da40cc47b4598c9643b347035bb9"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "179a9f4f36547f4ea60a196e670fc58051fc3cdd6ecc8f08a0a10256c7b443a402b852a75f1c38b1fffe3ec7f3"; got != want {
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

		if got, want := hex.EncodeToString(sealDerive), "658908d1d91755d5fb37ed7c6dce9d3710d34a5ec539510ab64b8a5b31ea0355"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "a978e9131f73341787f605755deeebd76e94999933717117bdb5f2aa56ac15e9"; got != want {
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

		if got, want := hex.EncodeToString(seal1), "d681dd5ad476651843c17f3cfbc54763223f105b8d47366467f7f73cbc4be367b26ad6a6ae04fc3bd49d14ee45"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "2299b98eb976cf08820419f18f29f50fbf47cca91aa263faed9b18f7780a65166b19a9753b6ffc9c5bb93de6b736"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "a20c4d8f8eb687a8da1eeb5d6ddb8ca054c6d022bc0d0d4cbe97928e2928beaede3810f480c413abff9255d69f"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
