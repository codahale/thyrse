package hpke_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/hpke"
)

func TestOpen(t *testing.T) {
	drbg := testdata.New("thyrse hpke")
	dR, qR := drbg.KeyPair()
	dS, qS := drbg.KeyPair()
	dX, qX := drbg.KeyPair()
	r := drbg.Data(64)

	message := []byte("this is a message")
	ciphertext := hpke.Seal("hpke", qR, dS, r, message)

	t.Run("round trip", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, qS, ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := plaintext, message; !bytes.Equal(got, want) {
			t.Errorf("Open() = %x, want = %x", got, want)
		}
	})

	t.Run("wrong receiver", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dX, qS, ciphertext)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("wrong sender", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, qX, ciphertext)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad qE", func(t *testing.T) {
		badQE := slices.Clone(ciphertext)
		badQE[2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badQE)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad ciphertext", func(t *testing.T) {
		badCT := slices.Clone(ciphertext)
		badCT[34] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badCT)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})

	t.Run("bad tag", func(t *testing.T) {
		badTag := slices.Clone(ciphertext)
		badTag[len(badTag)-2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badTag)
		if err == nil {
			t.Errorf("Open = %x, want = ErrInvalidCiphertext", plaintext)
		}
	})
}

func FuzzOpen(f *testing.F) {
	drbg := testdata.New("thyrse hpke fuzz")
	for range 10 {
		f.Add(drbg.Data(128))
	}

	dR, qR := drbg.KeyPair()
	dS, qS := drbg.KeyPair()
	r := drbg.Data(64)

	ciphertext := hpke.Seal("hpke", qR, dS, r, []byte("this is a message"))

	badQE := slices.Clone(ciphertext)
	badQE[2] ^= 1
	f.Add(badQE)

	badCT := slices.Clone(ciphertext)
	badCT[34] ^= 1
	f.Add(badCT)

	badTag := slices.Clone(ciphertext)
	badTag[len(badTag)-2] ^= 1
	f.Add(badTag)

	f.Fuzz(func(t *testing.T, ct []byte) {
		if bytes.Equal(ct, ciphertext) {
			t.Skip()
		}

		plaintext, err := hpke.Open("hpke", dR, qS, ct)
		if err == nil {
			t.Errorf("Open(ciphertext=%x) = plaintext=%x, want = err", ct, plaintext)
		}
	})
}
