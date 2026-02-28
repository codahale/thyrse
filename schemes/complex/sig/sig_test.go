package sig_test

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/sig"
)

func TestSign(t *testing.T) {
	drbg := testdata.New("thyrse digital signature")
	d, _ := drbg.KeyPair()

	t.Run("successful", func(t *testing.T) {
		signature, err := sig.Sign("sig", d, drbg.Data(64), strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if got, want := len(signature), sig.Size; got != want {
			t.Errorf("len(signature) = %d, want %d", got, want)
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		_, err := sig.Sign("sig", d, drbg.Data(64), &testdata.ErrReader{Err: errors.New("broken")})
		if err == nil {
			t.Error("should have failed")
		}
	})
}

func TestVerify(t *testing.T) {
	drbg := testdata.New("thyrse digital signature")
	d, q := drbg.KeyPair()
	_, qX := drbg.KeyPair()

	signature, err := sig.Sign("sig", d, drbg.Data(64), strings.NewReader("this is a message"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if !valid {
			t.Errorf("Verify() = false, want = true")
		}
	})

	t.Run("short signature", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature[:sig.Size-1], strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("Verify() = true, want = false")
		}
	})

	t.Run("long signature", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, append(signature, 0), strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("Verify() = true, want = false")
		}
	})

	t.Run("reader failure", func(t *testing.T) {
		_, err := sig.Verify("sig", q, signature, &testdata.ErrReader{Err: errors.New("broken")})
		if err == nil {
			t.Error("should have failed")
		}
	})

	t.Run("wrong signer", func(t *testing.T) {
		valid, err := sig.Verify("sig", qX, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		valid, err := sig.Verify("sig", q, signature, strings.NewReader("this is another message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
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
			t.Errorf("should not have been valid")
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
			t.Errorf("should not have been valid")
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
			t.Error("should not have been valid")
		}
	})

	t.Run("domain mismatch", func(t *testing.T) {
		valid, err := sig.Verify("wrong domain", q, signature, strings.NewReader("this is a message"))
		if err != nil {
			t.Fatal(err)
		}

		if valid {
			t.Errorf("should not have been valid")
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
			t.Errorf("Verify(signature=%x, message=%x) = true, want = false", signature, message)
		}
	})
}
