package vrf_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/vrf"
)

func TestVerify(t *testing.T) {
	drbg := testdata.New("thyrse vrf")
	d, q := drbg.KeyPair()
	_, qX := drbg.KeyPair()
	r := drbg.Data(64)

	prf, proof := vrf.Prove("domain", d, r, []byte("message"), 32)

	t.Run("valid", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("message"), proof, 32)
		if !valid {
			t.Errorf("Verify() = false, want = true")
		}

		if got, want := got, prf; !bytes.Equal(got, want) {
			t.Errorf("Verify() output = %x, want = %x", got, want)
		}
	})

	t.Run("wrong prover", func(t *testing.T) {
		valid, got := vrf.Verify("domain", qX, []byte("message"), proof, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("Verify() output = %x, want = nil", got)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		valid, got := vrf.Verify("other domain", q, []byte("message"), proof, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("wrong message", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("other message"), proof, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("wrong length", func(t *testing.T) {
		valid, got := vrf.Verify("domain", q, []byte("message"), proof, 22)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad c", func(t *testing.T) {
		badC := slices.Clone(proof)
		badC[0] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badC, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad r", func(t *testing.T) {
		badR := slices.Clone(proof)
		badR[33] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badR, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})

	t.Run("bad gamma", func(t *testing.T) {
		badGamma := slices.Clone(proof)
		badGamma[62] ^= 1

		valid, got := vrf.Verify("domain", q, []byte("message"), badGamma, 32)
		if valid {
			t.Errorf("Verify() = true, want = false")
		}

		if got != nil {
			t.Errorf("got = %x, want = nil", got)
		}
	})
}

func FuzzVerify(f *testing.F) {
	drbg := testdata.New("thyrse vrf fuzz")
	_, q := drbg.KeyPair()

	for range 10 {
		f.Add(drbg.Data(vrf.ProofSize), drbg.Data(32))
	}

	f.Fuzz(func(t *testing.T, proof, message []byte) {
		valid, prf := vrf.Verify("fuzz", q, message, proof, 32)
		if valid {
			t.Errorf("Verify(message=%x, proof=%x) = (true, prf=%x), want = false", message, proof, prf)
		}
	})
}
