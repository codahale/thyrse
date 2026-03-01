// Package sig implements an EdDSA-style Schnorr digital signature scheme using Ristretto255 and Thyrse.
package sig

import (
	"bytes"
	"io"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// Size is the length of a signature in bytes.
const Size = 64

// Sign uses the given Ristretto255 private key and an optional slice of random data to generate a strongly unforgeable
// digital signature of the reader's contents.
//
// Returns any error from the underlying reader.
func Sign(domain string, d *ristretto255.Scalar, rand []byte, message io.Reader) ([]byte, error) {
	// Initialize the protocol and mix in the signer's public key and the message.
	p := thyrse.New(domain)
	p.Mix("signer", ristretto255.NewIdentityElement().ScalarBaseMult(d).Bytes())
	w := p.MixWriter("message")
	_, err := io.Copy(w, message)
	if err != nil {
		return nil, err
	}
	// Close() error is explicitly ignored here because MixWriter.Close() only returns an error
	// if the underlying writer returns an error, and io.Discard never returns errors.
	_ = w.Close()

	// Fork the protocol into prover/verifier roles and mix both the signer's private key and the provided random data
	// (if any) into the prover.
	prover, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))
	prover.Mix("signer-private", d.Bytes())
	prover.Mix("hedged-rand", rand)

	// Use the prover to derive a commitment scalar and commitment point which is guaranteed to be unique for the
	// combination of signer and message. This eliminates the risk of private key recovery via nonce reuse, and the
	// user-provided random data hedges the deterministic scheme against fault attacks.
	k, _ := ristretto255.NewScalar().SetUniformBytes(prover.Derive("commitment", nil, 64))
	r := ristretto255.NewIdentityElement().ScalarBaseMult(k)
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

	// Initialize the protocol and mix in the signer's public key and the message.
	p := thyrse.New(domain)
	p.Mix("signer", q.Bytes())
	w := p.MixWriter("message")
	_, err := io.Copy(w, message)
	if err != nil {
		return false, err
	}
	// Close() error is explicitly ignored here because MixWriter.Close() only returns an error
	// if the underlying writer returns an error, and io.Discard never returns errors.
	_ = w.Close()

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
