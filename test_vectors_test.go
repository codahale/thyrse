package thyrse_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/codahale/thyrse"
)

type testVectorFile struct {
	Vectors []testVector `json:"vectors"`
}

type testVector struct {
	ID        string            `json:"id"`
	Title     string            `json:"title"`
	InitLabel string            `json:"init_label"`
	Expected  map[string]string `json:"expected"`
}

func loadVectors(t *testing.T) testVectorFile {
	t.Helper()
	data, err := os.ReadFile("docs/thyrse-test-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f testVectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func vecByID(t *testing.T, f testVectorFile, id string) testVector {
	t.Helper()
	for _, v := range f.Vectors {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("vector %s not found", id)
	return testVector{}
}

func expectHex(t *testing.T, vec testVector, key string) string {
	t.Helper()
	v, ok := vec.Expected[key]
	if !ok {
		t.Fatalf("vector %s missing expected key %q", vec.ID, key)
	}
	return v
}

// TestVectors verifies the Go implementation against the shared test vectors in
// docs/thyrse-test-vectors.json (the single source of truth for §12).

func TestVectors(t *testing.T) {
	f := loadVectors(t)

	t.Run("InitDerive", func(t *testing.T) {
		vec := vecByID(t, f, "12.1")
		p := thyrse.New(vec.InitLabel)
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), expectHex(t, vec, "derive"); got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MixMixDerive", func(t *testing.T) {
		vec := vecByID(t, f, "12.2")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), expectHex(t, vec, "derive"); got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealDerive", func(t *testing.T) {
		vec := vecByID(t, f, "12.3")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		seal := p.Seal("message", nil, []byte("hello, world!"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(seal), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(derive), expectHex(t, vec, "derive"); got != want {
			t.Errorf("Derive = %s, want = %s", got, want)
		}
	})

	t.Run("MaskSeal", func(t *testing.T) {
		vec := vecByID(t, f, "12.4")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		mask := p.Mask("unauthenticated", nil, []byte("mask this data"))
		seal := p.Seal("authenticated", nil, []byte("seal this data"))

		if got, want := hex.EncodeToString(mask), expectHex(t, vec, "mask"); got != want {
			t.Errorf("Mask = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(seal), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}
	})

	t.Run("DeriveNoRatchet", func(t *testing.T) {
		vec := vecByID(t, f, "12.5.1")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), expectHex(t, vec, "derive"); got != want {
			t.Errorf("Derive (no Ratchet) = %s, want = %s", got, want)
		}
	})

	t.Run("RatchetDerive", func(t *testing.T) {
		vec := vecByID(t, f, "12.5.2")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		p.Ratchet("forward-secrecy")
		derive := p.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(derive), expectHex(t, vec, "derive"); got != want {
			t.Errorf("Derive (after Ratchet) = %s, want = %s", got, want)
		}
	})

	t.Run("ForkDerive", func(t *testing.T) {
		vec := vecByID(t, f, "12.6")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		left, right := p.Fork("role", []byte("prover"), []byte("verifier"))
		base := p.Derive("output", nil, 32)
		leftDerive := left.Derive("output", nil, 32)
		rightDerive := right.Derive("output", nil, 32)

		if got, want := hex.EncodeToString(base), expectHex(t, vec, "base_derive"); got != want {
			t.Errorf("Base Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(leftDerive), expectHex(t, vec, "clone_1_derive"); got != want {
			t.Errorf("Prover Derive = %s, want = %s", got, want)
		}
		if got, want := hex.EncodeToString(rightDerive), expectHex(t, vec, "clone_2_derive"); got != want {
			t.Errorf("Verifier Derive = %s, want = %s", got, want)
		}
	})

	t.Run("SealOpenRoundTrip", func(t *testing.T) {
		vec := vecByID(t, f, "12.7")
		key := []byte("test-key-material")
		nonce := []byte("test-nonce-value")
		ad := []byte("associated data")
		plaintext := []byte("hello, world!")

		// Seal side.
		pSeal := thyrse.New(vec.InitLabel)
		pSeal.Mix("key", key)
		pSeal.Mix("nonce", nonce)
		pSeal.Mix("ad", ad)
		sealed := pSeal.Seal("message", nil, plaintext)
		sealDerive := pSeal.Derive("confirm", nil, 32)

		// Open side.
		pOpen := thyrse.New(vec.InitLabel)
		pOpen.Mix("key", key)
		pOpen.Mix("nonce", nonce)
		pOpen.Mix("ad", ad)
		opened, err := pOpen.Open("message", nil, sealed)
		if err != nil {
			t.Fatal(err)
		}
		openDerive := pOpen.Derive("confirm", nil, 32)

		if got, want := hex.EncodeToString(sealed), expectHex(t, vec, "seal"); got != want {
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
		vec := vecByID(t, f, "12.8")
		key := []byte("test-key-material")
		nonce := []byte("test-nonce-value")
		plaintext := []byte("hello, world!")

		// Seal side.
		pSeal := thyrse.New(vec.InitLabel)
		pSeal.Mix("key", key)
		pSeal.Mix("nonce", nonce)
		sealed := pSeal.Seal("message", nil, plaintext)
		sealDerive := pSeal.Derive("after", nil, 32)

		if got, want := hex.EncodeToString(sealed), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal = %s, want = %s", got, want)
		}

		// Tamper with ciphertext (flip first byte).
		tampered := make([]byte, len(sealed))
		copy(tampered, sealed)
		tampered[0] ^= 0xff

		// Open side with tampered data.
		pOpen := thyrse.New(vec.InitLabel)
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

	t.Run("MultipleSeals1", func(t *testing.T) {
		vec := vecByID(t, f, "12.9.1")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		seal := p.Seal("msg", nil, []byte("first message"))

		if got, want := hex.EncodeToString(seal), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal 1 = %s, want = %s", got, want)
		}
	})

	t.Run("MultipleSeals2", func(t *testing.T) {
		vec := vecByID(t, f, "12.9.2")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		p.Seal("msg", nil, []byte("first message"))
		seal := p.Seal("msg", nil, []byte("second message"))

		if got, want := hex.EncodeToString(seal), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal 2 = %s, want = %s", got, want)
		}
	})

	t.Run("MultipleSeals3", func(t *testing.T) {
		vec := vecByID(t, f, "12.9.3")
		p := thyrse.New(vec.InitLabel)
		p.Mix("key", []byte("test-key-material"))
		p.Mix("nonce", []byte("test-nonce-value"))
		p.Seal("msg", nil, []byte("first message"))
		p.Seal("msg", nil, []byte("second message"))
		seal := p.Seal("msg", nil, []byte("third message"))

		if got, want := hex.EncodeToString(seal), expectHex(t, vec, "seal"); got != want {
			t.Errorf("Seal 3 = %s, want = %s", got, want)
		}
	})
}
