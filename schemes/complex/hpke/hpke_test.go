package hpke_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/hpke"
	"github.com/gtank/ristretto255"
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
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("wrong sender", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, qX, ciphertext)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("identity sender", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", dR, ristretto255.NewIdentityElement(), ciphertext)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("identity receiver", func(t *testing.T) {
		plaintext, err := hpke.Open("hpke", ristretto255.NewScalar(), qS, ciphertext)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("identity ephemeral", func(t *testing.T) {
		identityQE := slices.Clone(ciphertext)
		copy(identityQE[:32], ristretto255.NewIdentityElement().Bytes())
		plaintext, err := hpke.Open("hpke", dR, qS, identityQE)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("bad qE", func(t *testing.T) {
		badQE := slices.Clone(ciphertext)
		badQE[2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badQE)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("bad ciphertext", func(t *testing.T) {
		badCT := slices.Clone(ciphertext)
		badCT[34] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badCT)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})

	t.Run("bad tag", func(t *testing.T) {
		badTag := slices.Clone(ciphertext)
		badTag[len(badTag)-2] ^= 1

		plaintext, err := hpke.Open("hpke", dR, qS, badTag)
		if err == nil {
			t.Errorf("Open() = %x, want error", plaintext)
		}
	})
}

func TestSealRejectsIdentityKeys(t *testing.T) {
	drbg := testdata.New("thyrse hpke identity")
	_, qR := drbg.KeyPair()
	dS, _ := drbg.KeyPair()

	for name, f := range map[string]func(){
		"receiver": func() { hpke.Seal("hpke", ristretto255.NewIdentityElement(), dS, drbg.Data(64), nil) },
		"sender":   func() { hpke.Seal("hpke", qR, ristretto255.NewScalar(), drbg.Data(64), nil) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Seal() did not panic")
				}
			}()
			f()
		})
	}
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
