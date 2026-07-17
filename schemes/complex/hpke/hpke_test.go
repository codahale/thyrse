package hpke_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"slices"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/hpke"
)

const testHeaderSize = 32 + mlkem.CiphertextSize768

func TestOpen(t *testing.T) {
	drbg := testdata.New("thyrse hpke")
	dR, qR := x25519KeyPair(drbg)
	kR := mlkemKey(t, drbg)
	dX, _ := x25519KeyPair(drbg)
	kX := mlkemKey(t, drbg)

	message := []byte("this is a message")
	ciphertext := hpke.Seal("hpke", qR, kR.EncapsulationKey(), message)

	t.Run("round trip", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, kR, ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := plaintext, message; !bytes.Equal(got, want) {
			t.Errorf("Open() = %x, want = %x", got, want)
		}
	})

	t.Run("wrong X25519 receiver", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dX, kR, ciphertext)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("wrong ML-KEM receiver", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, kX, ciphertext)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("low-order ephemeral", func(t *testing.T) {
		modified := slices.Clone(ciphertext)
		clear(modified[:32])
		plaintext, err := hpke.Open("hpke", dR, kR, modified)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("modified ephemeral", func(t *testing.T) {
		modified := slices.Clone(ciphertext)
		modified[2] ^= 1
		plaintext, err := hpke.Open("hpke", dR, kR, modified)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("modified ML-KEM ciphertext", func(t *testing.T) {
		modified := slices.Clone(ciphertext)
		modified[32] ^= 1
		plaintext, err := hpke.Open("hpke", dR, kR, modified)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("modified ciphertext", func(t *testing.T) {
		modified := slices.Clone(ciphertext)
		modified[testHeaderSize+2] ^= 1
		plaintext, err := hpke.Open("hpke", dR, kR, modified)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("modified tag", func(t *testing.T) {
		modified := slices.Clone(ciphertext)
		modified[len(modified)-2] ^= 1
		plaintext, err := hpke.Open("hpke", dR, kR, modified)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})
}

func TestSealRejectsLowOrderReceiver(t *testing.T) {
	drbg := testdata.New("thyrse hpke low order")
	kR := mlkemKey(t, drbg)
	lowOrder, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Seal() did not panic")
		}
	}()
	hpke.Seal("hpke", lowOrder, kR.EncapsulationKey(), nil)
}

func TestOverhead(t *testing.T) {
	if got, want := hpke.Overhead, testHeaderSize+thyrse.TagSize; got != want {
		t.Errorf("Overhead = %d, want = %d", got, want)
	}
}

func FuzzOpen(f *testing.F) {
	drbg := testdata.New("thyrse hpke fuzz")
	for range 10 {
		f.Add(drbg.Data(128))
	}

	dR, qR := x25519KeyPair(drbg)
	kR, err := mlkem.NewDecapsulationKey768(drbg.Data(mlkem.SeedSize))
	if err != nil {
		f.Fatal(err)
	}
	ciphertext := hpke.Seal("hpke", qR, kR.EncapsulationKey(), []byte("this is a message"))

	modifiedEphemeral := slices.Clone(ciphertext)
	modifiedEphemeral[2] ^= 1
	f.Add(modifiedEphemeral)

	modifiedKEM := slices.Clone(ciphertext)
	modifiedKEM[32] ^= 1
	f.Add(modifiedKEM)

	modifiedCiphertext := slices.Clone(ciphertext)
	modifiedCiphertext[testHeaderSize+2] ^= 1
	f.Add(modifiedCiphertext)

	modifiedTag := slices.Clone(ciphertext)
	modifiedTag[len(modifiedTag)-2] ^= 1
	f.Add(modifiedTag)

	f.Fuzz(func(t *testing.T, ct []byte) {
		if bytes.Equal(ct, ciphertext) {
			t.Skip()
		}

		plaintext, err := hpke.Open("hpke", dR, kR, ct)
		if err == nil {
			t.Errorf("Open(ciphertext=%x) = plaintext=%x, want = err", ct, plaintext)
		}
	})
}

func x25519KeyPair(drbg *testdata.DRBG) (*ecdh.PrivateKey, *ecdh.PublicKey) {
	private, err := ecdh.X25519().NewPrivateKey(drbg.Data(32))
	if err != nil {
		panic(err)
	}
	return private, private.PublicKey()
}

func mlkemKey(t *testing.T, drbg *testdata.DRBG) *mlkem.DecapsulationKey768 {
	t.Helper()
	key, err := mlkem.NewDecapsulationKey768(drbg.Data(mlkem.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	return key
}
