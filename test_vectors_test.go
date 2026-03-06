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

		if got, want := hex.EncodeToString(seal), "9c756dac34249238b2d9b6e1e80ba8f52b5c3513efdb22a6c07203e01c803706fde799fc37632b2f4f80a72d7c"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "d17ca0c8f55c16a27cde9a59fb914fd3662709205ef1f85c1a9d9c6f689b07a8"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "664cfab3c70616512190c570fb48"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "7cfa9d55e33a88c9a8c7981c1020b3b2d2425fe2aa09d9d705a779e6b729c4b018f366fd9502dcdbe67d7b53f37c"; got != want {
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

	t.Run("MixDigest", func(t *testing.T) {
		// §16.7: MixDigest — pre-hash of a 10000-byte input via KT128.
		data := make([]byte, 10000)
		for i := range data {
			data[i] = byte(i % 251)
		}

		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		if err := p.MixDigest("stream-data", bytes.NewReader(data)); err != nil {
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

		if got, want := hex.EncodeToString(sealed), "917765a7fc3bbc419ff0e7bd2421f046c271efa6821eaa85189bcf7fef03c573db06d232fba2a84532b9e2bdc6"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if got, want := hex.EncodeToString(sealDerive), "b5f396cae3922fabe9e95dc693d43495f934b1b7bcb5bdc0eb49e714632ec2b1"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "b5f396cae3922fabe9e95dc693d43495f934b1b7bcb5bdc0eb49e714632ec2b1"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "bd579d0b0b0c599249ff814060e84b5ac1cc4986a3e56475d8919fc8a79a5ad2c3cb9ec2720b96fa8ec040fb60"; got != want {
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

		if got, want := hex.EncodeToString(sealDerive), "4489d6b22d87f426e6d4736462ad503f294c5303dc0b9449fca7781c4b76503c"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "51a7b45f0ab22bb91e9651eb64e1fcc3b4f6bcc4ee17d0b4787e98cd2fdc3178"; got != want {
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

		if got, want := hex.EncodeToString(seal1), "4d77468e708f5eb9b077df3c35539615cf87ca19dff98a98ca27af9c03fe313195d0bf1c28f5979c36cdde7c96"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "e879742b2273d5570bf1bae372ddeb1490c901dc8f609531a688fcdbde454a4e72f7b05f1f19391f49af6fe7bc75"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "8f37a83a96a53474b2fc7c7a103f44b8f25309ea4476412f3d2d20e25ab40c1cbcdc826839fcb075961ec2f482"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
