// Package vrf implements a verifiable random function (VRF) using Ristretto255 and Thyrse.
package vrf

import (
	"slices"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// ProofSize is the size, in bytes, of a VRF proof.
const ProofSize = 32 + 32 + 32

// Prove generates n bytes of pseudorandom data for the given message and returns that and a proof which can be used to
// verify and recalculate the PRF output given the message and the prover's public key.
func Prove(domain string, d *ristretto255.Scalar, rand, m []byte, n int) (prf, proof []byte) {
	// Hash the input to a point on the curve.
	p := thyrse.New(domain)
	p.Mix("generator", ristretto255.NewGeneratorElement().Bytes())
	p.Mix("prover", ristretto255.NewIdentityElement().ScalarBaseMult(d).Bytes())
	p.Mix("input", m)
	h, _ := ristretto255.NewIdentityElement().SetUniformBytes(p.Derive("point", nil, 64))

	// Calculate gamma and the PRF output.
	gamma := ristretto255.NewIdentityElement().ScalarMult(d, h)
	p.Mix("gamma", gamma.Bytes())
	prf = p.Derive("prf", nil, n)

	// Fork the protocol into prover and verifier roles.
	prover, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))

	// Calculate a hedged nonce k.
	prover.Mix("prover-private", d.Bytes())
	prover.Mix("rand", rand)
	k, _ := ristretto255.NewScalar().SetUniformBytes(prover.Derive("commitment", nil, 64))

	// Calculate the commitment points.
	u := ristretto255.NewIdentityElement().ScalarBaseMult(k)
	v := ristretto255.NewIdentityElement().ScalarMult(k, h)
	verifier.Mix("commitment-u", u.Bytes())
	verifier.Mix("commitment-v", v.Bytes())

	// Calculate a challenge and a response.
	c, _ := ristretto255.NewScalar().SetUniformBytes(verifier.Derive("challenge", nil, 64))
	s := ristretto255.NewScalar().Multiply(c, d)
	s = s.Add(s, k)

	// Return the PRF output and the proof.
	return prf, slices.Concat(gamma.Bytes(), c.Bytes(), s.Bytes())
}

// Verify checks the given proof against the given message. If the proof is valid, returns true and n bytes of PRF
// output; otherwise, returns false and nil.
func Verify(domain string, q *ristretto255.Element, m, proof []byte, n int) (valid bool, prf []byte) {
	if len(proof) != ProofSize {
		return false, nil
	}

	// Parse the proof.
	proofGamma := proof[:32]
	gamma, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(proofGamma)
	c, _ := ristretto255.NewScalar().SetCanonicalBytes(proof[32:64])
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(proof[64:])
	if c == nil || s == nil || gamma == nil {
		return false, nil
	}

	// Hash the input to a point on the curve.
	p := thyrse.New(domain)
	p.Mix("generator", ristretto255.NewGeneratorElement().Bytes())
	p.Mix("prover", q.Bytes())
	p.Mix("input", m)
	h, _ := ristretto255.NewIdentityElement().SetUniformBytes(p.Derive("point", nil, 64))

	// Mix in gamma and calculate the PRF output.
	p.Mix("gamma", proofGamma)
	prf = p.Derive("prf", nil, n)

	// Calculate the commitment points.
	negC := ristretto255.NewScalar().Negate(c)
	u := ristretto255.NewIdentityElement().VarTimeDoubleScalarBaseMult(negC, q, s)
	v := ristretto255.NewIdentityElement().VarTimeMultiScalarMult([]*ristretto255.Scalar{s, negC}, []*ristretto255.Element{h, gamma})

	// Fork the protocol into prover and verifier roles.
	_, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))

	verifier.Mix("commitment-u", u.Bytes())
	verifier.Mix("commitment-v", v.Bytes())

	// Calculate a challenge and a response.
	expectedC, _ := ristretto255.NewScalar().SetUniformBytes(verifier.Derive("challenge", nil, 64))
	if expectedC.Equal(c) == 0 {
		return false, nil
	}

	return true, prf
}
