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

		if got, want := hex.EncodeToString(seal), "6575e3876b0219f2a686eebd749200a586f1d26f432fd783696adee5ad9a6d8371116c771fded52b0678ec2e0e"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "d7347283ee4277967e116c944cf920c3207ac5ca0e4c8247150741f7b2a60de3"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "053316f985c11ca6a7a17e47c730"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "1c3a40fd2005162e83f5705393168a7784f6994be455a6388bf1bb74754bc69fa3e359af58d2902ebb1187033864"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "1a129733635a1c74cb2ac0e333092d93a88ed061157931bf87ba74333f22b4c101e5d05dea339a9f1b8432f840"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if got, want := hex.EncodeToString(sealDerive), "799fecc5f0b8caf37e8462a8f1e93bccf6c64cbd648701eb4a921ccd8056ed36"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "799fecc5f0b8caf37e8462a8f1e93bccf6c64cbd648701eb4a921ccd8056ed36"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "1109d74f77b6c1042fc1d0a8808a545f5eab14badb21aa34a948bd2e4178f23959b4ac63f5f6ea144cd4a5da45"; got != want {
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

		if got, want := hex.EncodeToString(sealDerive), "cf2346cd8215390302f0ddf7bfbddce69db99b6200bf8d1ca5a51a69679f2a4f"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "423fb570826f9aad65cef6d4d0e77ee0de7d5f7c400b0a894321687ee6804ab7"; got != want {
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

		if got, want := hex.EncodeToString(seal1), "928886931c90fcf68b6d7193420acf444c3310164db95d790029971b077b1f82e2efa31fca13fda81fb95f3f8f"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "ec0fdeed2b4cfd43aee710ee16cd2e6fd15395e46da7b520d6dd6760dbe309f04730bb922cd8c491b568d530f0be"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "c6ee6e5173a6a7c5e37d928b84bb2de985a8d1ea13d6b94bc4123a35f2074191977ff4f532cc00d450f1bade4e"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
