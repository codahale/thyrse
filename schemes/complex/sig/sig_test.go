package sig_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/sig"
	"github.com/gtank/ristretto255"
)

func TestSign(t *testing.T) {
	drbg := testdata.New("thyrse digital signature")
	d, _ := drbg.KeyPair()

	t.Run("successful", func(t *testing.T) {
		signature, err := sig.Sign("sig", d, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if got, want := len(signature), sig.Size; got != want {
			t.Errorf("len(signature) = %d, want %d", got, want)
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		_, err := sig.Sign("sig", d, &testdata.ErrReader{Err: errors.New("broken")})
		if err == nil {
			t.Error("Sign() err = nil, want error")
		}
	})

	t.Run("identity signer", func(t *testing.T) {
		_, err := sig.Sign("sig", ristretto255.NewScalar(), strings.NewReader("this is a message"))
		if err == nil {
			t.Error("Sign() err = nil, want error")
		}
	})
}

func TestVerify(t *testing.T) {
	drbg := testdata.New("thyrse digital signature")
	d, q := drbg.KeyPair()
	_, qX := drbg.KeyPair()

	signature, err := sig.Sign("sig", d, strings.NewReader("this is a message"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if !valid {
			t.Error("Verify() = false, want true")
		}
	})

	t.Run("short signature", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature[:sig.Size-1], strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("long signature", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, append(signature, 0), strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		_, err := sig.Verify("sig", q, signature, &testdata.ErrReader{Err: errors.New("broken")})
		if err == nil {
			t.Error("Verify() err = nil, want error")
		}
	})

	t.Run("wrong signer", func(t *testing.T) {
		valid, err := sig.Verify("sig", qX, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("identity signer", func(t *testing.T) {
		// With Q=I, (R=[s]G, s) satisfies the verification equation for
		// every challenge unless the public key is rejected explicitly.
		s := d
		r := ristretto255.NewIdentityElement().ScalarBaseMult(s)
		forged := append(r.Bytes(), s.Bytes()...)
		valid, err := sig.Verify("sig", ristretto255.NewIdentityElement(), forged, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("identity commitment", func(t *testing.T) {
		badR := slices.Clone(signature)
		copy(badR[:32], ristretto255.NewIdentityElement().Bytes())
		valid, err := sig.Verify("sig", q, badR, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is another message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("wrong R", func(t *testing.T) {
		badI := slices.Clone(signature)
		badI[0] ^= 1
		valid, err := sig.Verify("sig", q, badI, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("wrong s", func(t *testing.T) {
		badS := slices.Clone(signature)
		badS[34] ^= 1
		valid, err := sig.Verify("sig", q, badS, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("non-canonical s", func(t *testing.T) {
		badS := slices.Clone(signature)
		for i := 32; i < 64; i++ {
			badS[i] = 0xff
		}
		valid, err := sig.Verify("sig", q, badS, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})

	t.Run("domain mismatch", func(t *testing.T) {
		valid, err := sig.Verify("wrong domain", q, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Error("Verify() = true, want false")
		}
	})
}

func FuzzVerify(f *testing.F) {
	drbg := testdata.New("thyrse sig fuzz")
	_, q := drbg.KeyPair()

	for range 10 {
		f.Add(drbg.Data(sig.Size), drbg.Data(32))
	}

	f.Fuzz(func(t *testing.T, signature, message []byte) {
		valid, err := sig.Verify("fuzz", q, signature, bytes.NewReader(message))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("Verify(signature=%x, message=%x) = true, want false", signature, message)
		}
	})
}
