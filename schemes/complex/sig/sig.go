// Package sig implements an EdDSA-style Schnorr digital signature scheme using Ristretto255 and Thyrse.
package sig

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// Size is the length of a signature in bytes.
const Size = 64

// Sign uses the given Ristretto255 private key to generate a strongly unforgeable digital signature of the reader's
// contents.
//
// Returns any error from the underlying reader.
func Sign(domain string, d *ristretto255.Scalar, message io.Reader) ([]byte, error) {
	q := ristretto255.NewIdentityElement().ScalarBaseMult(d)
	if q.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errors.New("sig: signer public key is identity")
	}

	// Initialize the protocol and mix in the signer's public key and the message.
	p := thyrse.New(domain)
	p.Mix("signer", q.Bytes())
	if err := mixReader(p, "message", message); err != nil {
		return nil, err
	}

	// Fork the protocol into prover/verifier roles and mix both the signer's private key and fresh random data into the
	// prover.
	var random [64]byte
	_, _ = rand.Read(random[:])
	prover, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))
	prover.Mix("signer-private", d.Bytes())
	prover.Mix("hedged-rand", random[:])
	clear(random[:])

	// Use the prover to derive a commitment scalar and commitment point which is guaranteed to be unique for the
	// combination of signer and message. This eliminates the risk of private key recovery via nonce reuse, and the
	// fresh random data hedges the deterministic scheme against fault attacks.
	k, _ := ristretto255.NewScalar().SetUniformBytes(prover.Derive("commitment", nil, 64))
	r := ristretto255.NewIdentityElement().ScalarBaseMult(k)
	if r.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errors.New("sig: commitment is identity")
	}
	rOut := r.Bytes()

	// Mix the commitment point into the verifier.
	verifier.Mix("commitment", rOut)

	// Derive a challenge scalar from the verifier.
	c, _ := ristretto255.NewScalar().SetUniformBytes(verifier.Derive("challenge", nil, 64))

	// Calculate the proof scalar s = k + d*c.
	s := ristretto255.NewScalar().Multiply(d, c)
	s = s.Add(s, k)
	return append(rOut, s.Bytes()...), nil
}

// Verify uses the given Ristretto255 public key and signature to verify the contents of the given reader. Returns true
// if and only if the signature was made of the message by the holder of the signer's private key.
//
// Returns any error from the underlying reader.
func Verify(domain string, q *ristretto255.Element, sig []byte, message io.Reader) (bool, error) {
	// Valid signatures consist of a 32-byte point and a 32-byte scalar.
	if len(sig) != Size {
		return false, nil
	}
	identity := ristretto255.NewIdentityElement()
	if q.Equal(identity) == 1 {
		return false, nil
	}
	r, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(sig[:32])
	if r == nil || r.Equal(identity) == 1 {
		return false, nil
	}

	// Initialize the protocol and mix in the signer's public key and the message.
	p := thyrse.New(domain)
	p.Mix("signer", q.Bytes())
	if err := mixReader(p, "message", message); err != nil {
		return false, err
	}

	// Fork the protocol, keeping only the verifier.
	_, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))

	// Mix the received commitment point into the verifier. As we do not use it for calculations, leave it encoded.
	verifier.Mix("commitment", sig[:32])

	// Derive an expected challenge scalar from the signer's public key, the message, and the commitment point.
	c, _ := ristretto255.NewScalar().SetUniformBytes(verifier.Derive("challenge", nil, 64))

	// Decode the proof scalar. If not canonically encoded, the signature is invalid.
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(sig[32:])
	if s == nil {
		return false, nil
	}

	// Calculate the expected commitment point: R' = [s]G + [-c']Q
	expectedR := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(ristretto255.NewScalar().Negate(c), q, s)

	// If the received and expected commitment points are equal (as compared in their encoded forms), the signature is
	// valid.
	return bytes.Equal(sig[:32], expectedR.Bytes()), nil
}

func mixReader(p *thyrse.Protocol, label string, r io.Reader) error {
	w := p.MixWriter(label)
	if _, err := io.Copy(w, r); err != nil {
		return errors.Join(err, w.Close())
	}
	return w.Close()
}
