package signcrypt_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/signcrypt"
	"github.com/gtank/ristretto255"
)

func TestOpen(t *testing.T) {
	r, dS, qS, dR, qR, dX, qX := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

	t.Run("valid", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, ciphertext)
		if err != nil {
			t.Fatal(err)
		}

		if got, want := plaintext, []byte("this is a message"); !bytes.Equal(got, want) {
			t.Errorf("Open() = %x, want = %x", got, want)
		}
	})

	t.Run("wrong receiver", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dX, qS, ciphertext)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("wrong sender", func(t *testing.T) {
		plaintext, err := signcrypt.Open("signcrypt", dR, qX, ciphertext)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid ephemeral public key", func(t *testing.T) {
		badQE := slices.Clone(ciphertext)
		badQE[0] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badQE)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid message", func(t *testing.T) {
		badM := slices.Clone(ciphertext)
		badM[33] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badM)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid I", func(t *testing.T) {
		badI := slices.Clone(ciphertext)
		badI[len(badI)-61] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badI)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})

	t.Run("invalid s", func(t *testing.T) {
		badS := slices.Clone(ciphertext)
		badS[len(badS)-30] ^= 1
		plaintext, err := signcrypt.Open("signcrypt", dR, qS, badS)
		if err == nil {
			t.Errorf("should not have been valid, unsigncrypted = %x", plaintext)
		}
	})
}

func BenchmarkSeal(b *testing.B) {
	r, dS, _, _, qR, _, _ := setup()
	message := []byte("this is a message")
	b.ReportAllocs()
	for b.Loop() {
		signcrypt.Seal("signcrypt", dS, qR, r, message)
	}
}

func BenchmarkOpen(b *testing.B) {
	r, dS, qS, dR, qR, _, _ := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

	b.ReportAllocs()
	for b.Loop() {
		_, _ = signcrypt.Open("signcrypt", dR, qS, ciphertext)
	}
}

func FuzzOpen(f *testing.F) {
	drbg := testdata.New("thyrse signcrypt fuzz")
	for range 10 {
		f.Add(drbg.Data(128))
	}

	r, dS, qS, dR, qR, _, _ := setup()
	ciphertext := signcrypt.Seal("signcrypt", dS, qR, r, []byte("this is a message"))

	badQE := slices.Clone(ciphertext)
	badQE[0] ^= 1

	badCT := slices.Clone(ciphertext)
	badCT[33] ^= 1

	badI := slices.Clone(ciphertext)
	badI[len(badI)-60] ^= 1

	badS := slices.Clone(ciphertext)
	badS[len(badS)-20] ^= 1

	f.Add(badQE)
	f.Add(badCT)
	f.Add(badI)
	f.Add(badS)
	f.Fuzz(func(t *testing.T, modifiedCiphertext []byte) {
		if bytes.Equal(ciphertext, modifiedCiphertext) {
			t.Skip()
		}

		plaintext, err := signcrypt.Open("signcrypt", dR, qS, modifiedCiphertext)
		if !errors.Is(err, thyrse.ErrInvalidCiphertext) {
			t.Errorf("Open(ciphertext=%x) = (plaintext=%x, err=%v), want = ErrInvalidCiphertext", modifiedCiphertext, plaintext, err)
		}
	})
}

func setup() ([]byte, *ristretto255.Scalar, *ristretto255.Element, *ristretto255.Scalar, *ristretto255.Element, *ristretto255.Scalar, *ristretto255.Element) {
	drbg := testdata.New("thyrse hpke")
	dR, qR := drbg.KeyPair()
	dS, qS := drbg.KeyPair()
	dX, qX := drbg.KeyPair()
	return drbg.Data(64), dS, qS, dR, qR, dX, qX
}
