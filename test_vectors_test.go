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

		if got, want := hex.EncodeToString(seal), "bffe6b98c777359053bec027468a01f175214de7378980683a0e76303eda635c10d0b75752f41fc234e14ecf83"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		if got, want := hex.EncodeToString(derive), "edf55a26dabc6e13c0b5bea7bab468ca00987d9d09b30f9e903c069b14f7b25e"; got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		// §16.4: Init + Mix + Mask + Seal — combined unauthenticated and authenticated encryption.
		p := thyrse.New("test.vector")
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), "315eef8f027514998149c0ca0b58"; got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), "248a23b4df4b9a6f6238bcb9107c677f2f74e74da8e292c17c91b6713f6a1660a4107f7fd1eb8027ed377ad733a8"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "45bd2b670e036c5bfea70787e1fbb28ff2b4f14077fa229dc49a3da8c64b89213cd9db0d0d7690fa6717a3877c"; got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if !bytes.Equal(opened, plaintext) {
			t.Errorf("Open plaintext = %x, want = %x", opened, plaintext)
		}
		if got, want := hex.EncodeToString(sealDerive), "9bcc1a5823f05b7e5868ff612ba37feb86376916a8b3235409c52db755366276"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "9bcc1a5823f05b7e5868ff612ba37feb86376916a8b3235409c52db755366276"; got != want {
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

		if got, want := hex.EncodeToString(sealed), "10b878ccd11cd133e2f360c420d7fb4281941355932fc0a35a173102bce64228d40f093e4b52842c722646c860"; got != want {
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

		if got, want := hex.EncodeToString(sealDerive), "a6a92c179feec190b5152a704f11f96925da2ece0d400412bc7f36fe2cdf0a70"; got != want {
			t.Errorf("Seal-side Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(openDerive), "2afc3800ce8f6e5a0f8392c7701e5a1d8274e9967c380c4d4117e29e9905767a"; got != want {
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

		if got, want := hex.EncodeToString(seal1), "d37ffa7172f0119840e8a329bf8269a0e1ce71afbd625f393d1858b50de62b18b90d8e4af0881457020a9fc851"; got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal2), "dd6618db4126b6d9ed7c1884e6e39fdab4d12cb9e414eaa0fa78c806c4db44078e685c682c87c7d2185ae2775a82"; got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal3), "01f79a0a5ad4b33bc6e46650b81e1d89cf24088a87e8347a342891803075e5ad77ec1cc7dafb8854d6a9480ee9"; got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
