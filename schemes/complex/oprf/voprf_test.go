package oprf_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/complex/oprf"
	"github.com/gtank/ristretto255"
)

func Example_voprf() {
	drbg := testdata.New("thyrse voprf")

	// The server has a private key.
	d, q := drbg.KeyPair()

	// The client has a secret input and blinds it.
	input := []byte("this is a sensitive input")
	blind, blindedElement, err := oprf.Blind("example", input)
	if err != nil {
		panic(err)
	}

	// The server evaluates the blinded input and returns a proof.
	evaluatedElement, c, s, err := oprf.VerifiableBlindEvaluate("example", d, blindedElement)
	if err != nil {
		panic(err)
	}

	// The client verifies the proof, finalizes it and derives PRF output.
	clientPRF, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
	if err != nil {
		panic(err)
	}
	fmt.Printf("client PRF = %x\n", clientPRF)

	// If the server gets the input, it can derive the same PRF output.
	serverPRF, err := oprf.Evaluate("example", d, input, 16)
	if err != nil {
		panic(err)
	}
	fmt.Printf("server PRF = %x\n", serverPRF)

	// Output:
	// client PRF = 70310ca3453a67eee661ed1ab36c281b
	// server PRF = 70310ca3453a67eee661ed1ab36c281b
}

func TestVerifiableFinalize(t *testing.T) {
	drbg := testdata.New("thyrse voprf")
	d, q := drbg.KeyPair()
	input := []byte("this is a sensitive input")

	blind, blindedElement, err := oprf.Blind("example", input)
	if err != nil {
		t.Fatal(err)
	}

	evaluatedElement, c, s, err := oprf.VerifiableBlindEvaluate("example", d, blindedElement)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid proof", func(t *testing.T) {
		_, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err != nil {
			t.Errorf("VerifiableFinalize failed: %v", err)
		}
	})

	t.Run("wrong domain", func(t *testing.T) {
		_, err := oprf.VerifiableFinalize("wrong domain", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err == nil {
			t.Error("should have failed with wrong domain")
		}
	})

	t.Run("wrong c", func(t *testing.T) {
		badC, _ := ristretto255.NewScalar().SetUniformBytes(bytes.Repeat([]byte{1}, 64))
		_, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, badC, s, 16)
		if err == nil {
			t.Error("should have failed with wrong c")
		}
	})

	t.Run("wrong s", func(t *testing.T) {
		badS, _ := ristretto255.NewScalar().SetUniformBytes(bytes.Repeat([]byte{2}, 64))
		_, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, badS, 16)
		if err == nil {
			t.Error("should have failed with wrong s")
		}
	})

	t.Run("identity points", func(t *testing.T) {
		input := []byte("this is a sensitive input")
		blind := ristretto255.NewScalar()
		q := ristretto255.NewIdentityElement()
		evaluatedElement := ristretto255.NewIdentityElement()
		blindedElement := ristretto255.NewIdentityElement()
		c := ristretto255.NewScalar()
		s := ristretto255.NewScalar()

		_, err := oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err == nil {
			t.Error("should have failed with identity public key")
		}

		q = ristretto255.NewGeneratorElement()
		_, err = oprf.VerifiableFinalize("example", input, blind, q, evaluatedElement, blindedElement, c, s, 16)
		if err == nil {
			t.Error("should have failed with identity blinded/evaluated elements")
		}
	})
}

func TestVerifiableBlindEvaluate(t *testing.T) {
	t.Run("identity points", func(t *testing.T) {
		d := ristretto255.NewScalar()
		blindedElement := ristretto255.NewIdentityElement()

		_, _, _, err := oprf.VerifiableBlindEvaluate("example", d, blindedElement)
		if err == nil {
			t.Error("should have failed with identity blinded element")
		}
	})
}

func FuzzVOPRF(f *testing.F) {
	drbg := testdata.New("thyrse voprf fuzz")
	_, q := drbg.KeyPair()

	for range 10 {
		blind, _ := ristretto255.NewScalar().SetUniformBytes(drbg.Data(64))
		evaluated, _ := ristretto255.NewIdentityElement().SetUniformBytes(drbg.Data(64))
		blinded, _ := ristretto255.NewIdentityElement().SetUniformBytes(drbg.Data(64))
		c, _ := ristretto255.NewScalar().SetUniformBytes(drbg.Data(64))
		s, _ := ristretto255.NewScalar().SetUniformBytes(drbg.Data(64))
		f.Add(blind.Bytes(), drbg.Data(32), evaluated.Bytes(), blinded.Bytes(), c.Bytes(), s.Bytes())
	}

	f.Fuzz(func(t *testing.T, blindB, input, evaluatedB, blindedB, cB, sB []byte) {
		blind := ristretto255.NewScalar()
		if _, err := blind.SetCanonicalBytes(blindB); err != nil {
			t.Skip()
		}
		evaluated := ristretto255.NewIdentityElement()
		if _, err := evaluated.SetCanonicalBytes(evaluatedB); err != nil {
			t.Skip()
		}
		blinded := ristretto255.NewIdentityElement()
		if _, err := blinded.SetCanonicalBytes(blindedB); err != nil {
			t.Skip()
		}
		c := ristretto255.NewScalar()
		if _, err := c.SetCanonicalBytes(cB); err != nil {
			t.Skip()
		}
		s := ristretto255.NewScalar()
		if _, err := s.SetCanonicalBytes(sB); err != nil {
			t.Skip()
		}

		v, err := oprf.VerifiableFinalize("fuzz", input, blind, q, evaluated, blinded, c, s, 16)
		if err == nil {
			t.Errorf("VerifiableFinalize(input=%x, blind=%x, evaluated=%x, blinded=%x, c=%x, s=%x) = prf=%x, want = err", input, blind.Bytes(), evaluated.Bytes(), blinded.Bytes(), c.Bytes(), s.Bytes(), v)
		}
	})
}
