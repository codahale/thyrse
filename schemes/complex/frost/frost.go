// Package frost implements FROST (Flexible Round-Optimized Schnorr Threshold) signatures using Ristretto255 and
// Thyrse. FROST allows a threshold of signers to collaboratively produce a standard Schnorr signature without any
// single party learning the group's private key.
//
// The resulting signatures are standard Schnorr signatures compatible with [sig.Verify].
package frost

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/schemes/complex/sig"
	"github.com/gtank/ristretto255"
)

// SignatureSize is the size of a FROST signature in bytes (same as a standard Schnorr signature).
const SignatureSize = sig.Size

// ShareSize is the size of a signature share in bytes.
const ShareSize = 32

var (
	// ErrInvalidParameters is returned for invalid keygen or signing parameters.
	ErrInvalidParameters = errors.New("frost: invalid parameters")

	// ErrInvalidCommitment is returned when a commitment cannot be decoded.
	ErrInvalidCommitment = errors.New("frost: invalid commitment")

	// ErrInvalidShare is returned when a signature share cannot be decoded.
	ErrInvalidShare = errors.New("frost: invalid share")

	// ErrMissingSigner is returned when the signer's identifier is not found in the commitment list.
	ErrMissingSigner = errors.New("frost: signer not in commitment list")

	// ErrDuplicateIdentifier is returned when duplicate signer identifiers are detected in the commitment list.
	ErrDuplicateIdentifier = errors.New("frost: duplicate identifier in commitments")
)

// A Signer holds the secret key material for a single FROST participant.
type Signer struct {
	domain         string
	identifier     uint16
	signingShare   *ristretto255.Scalar
	verifyingShare *ristretto255.Element
	groupKey       *ristretto255.Element
}

// Identifier returns the signer's 1-based identifier.
func (s *Signer) Identifier() uint16 {
	return s.identifier
}

// VerifyingShare returns the signer's verifying share (public key corresponding to their signing share).
func (s *Signer) VerifyingShare() *ristretto255.Element {
	return s.verifyingShare
}

// GroupKey returns the group's public verifying key.
func (s *Signer) GroupKey() *ristretto255.Element {
	return s.groupKey
}

// A Nonce holds the ephemeral secret nonces for a single signing round. Each Nonce must be used exactly once and then
// discarded.
type Nonce struct {
	hiding  *ristretto255.Scalar
	binding *ristretto255.Scalar
}

// A Commitment is the public counterpart of a [Nonce], broadcast to all participants before signing.
type Commitment struct {
	Identifier uint16
	Hiding     []byte // 32-byte canonical element encoding.
	Binding    []byte // 32-byte canonical element encoding.
}

// KeyGen performs trusted-dealer key generation for a threshold-of-maxSigners FROST scheme. It returns the group public
// key, the signers (each containing their secret share and verifying share), and the verifying shares (public keys
// corresponding to each signer's share).
//
// Identifiers are 1-based: signers[i] has identifier i+1. The threshold must be at least 2 and at most maxSigners.
// rand must contain at least 64 bytes of uniform randomness.
func KeyGen(domain string, maxSigners, threshold int, rand []byte) (*ristretto255.Element, []Signer, []*ristretto255.Element, error) {
	if threshold < 2 || maxSigners < threshold || len(rand) < 64 {
		return nil, nil, nil, ErrInvalidParameters
	}

	// Derive polynomial coefficients deterministically from the seed.
	p := thyrse.New(domain)
	keygen, _ := p.Fork("process", []byte("keygen"), []byte("commitment"))
	keygen.Mix("seed", rand)

	coeffs := make([]*ristretto255.Scalar, threshold)
	for i := range threshold {
		coeffs[i], _ = ristretto255.NewScalar().SetUniformBytes(keygen.Derive("coefficient", nil, 64))
	}

	// The group public key is [a_0]G where a_0 is the secret.
	groupKey := ristretto255.NewIdentityElement().ScalarBaseMult(coeffs[0])

	// Evaluate the polynomial at each participant's identifier to produce shares.
	signers := make([]Signer, maxSigners)
	verifyingShares := make([]*ristretto255.Element, maxSigners)
	for i := range maxSigners {
		id := uint16(i + 1)
		share := evalPolynomial(coeffs, id)
		vs := ristretto255.NewIdentityElement().ScalarBaseMult(share)
		signers[i] = Signer{
			domain:         domain,
			identifier:     id,
			signingShare:   share,
			verifyingShare: vs,
			groupKey:       groupKey,
		}
		verifyingShares[i] = vs
	}

	return groupKey, signers, verifyingShares, nil
}

// Commit generates a nonce pair and its public commitment for a signing round. The rand parameter should contain at
// least 64 bytes of random data; the nonces are derived deterministically from the signer's share and the random data,
// providing hedged nonce generation that protects against both nonce reuse and weak randomness.
func (s *Signer) Commit(rand []byte) (Nonce, Commitment) {
	x := thyrse.New(s.domain)

	_, c := x.Fork("process", []byte("keygen"), []byte("commitment"))
	c.Mix("signing-share", s.signingShare.Bytes())
	c.Mix("rand", rand)

	hiding, _ := ristretto255.NewScalar().SetUniformBytes(c.Derive("hiding-nonce", nil, 64))
	binding, _ := ristretto255.NewScalar().SetUniformBytes(c.Derive("binding-nonce", nil, 64))

	return Nonce{hiding: hiding, binding: binding}, Commitment{
		Identifier: s.identifier,
		Hiding:     ristretto255.NewIdentityElement().ScalarBaseMult(hiding).Bytes(),
		Binding:    ristretto255.NewIdentityElement().ScalarBaseMult(binding).Bytes(),
	}
}

// Sign produces a signature share for the given message. The commitments slice must contain the commitments of all
// participants in this signing round, including this signer's own commitment. The nonce must be the same one returned
// by [Signer.Commit] for this round and must not be reused.
func (s *Signer) Sign(domain string, nonce Nonce, message []byte, commitments []Commitment) ([]byte, error) {
	sorted := sortCommitments(commitments)

	if err := validateCommitments(sorted, s.identifier); err != nil {
		return nil, err
	}

	bindingFactors, err := computeBindingFactors(domain, s.groupKey, message, sorted)
	if err != nil {
		return nil, err
	}

	groupCommitment, err := computeGroupCommitment(sorted, bindingFactors)
	if err != nil {
		return nil, err
	}

	challenge := computeChallenge(domain, s.groupKey, message, groupCommitment)

	identifiers := make([]uint16, len(sorted))
	for i, c := range sorted {
		identifiers[i] = c.Identifier
	}
	lambda := lagrangeCoefficient(s.identifier, identifiers)

	// z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c)
	rho := bindingFactors[s.identifier]
	z := ristretto255.NewScalar().Multiply(nonce.binding, rho)
	z.Add(z, nonce.hiding)
	lambdaSC := ristretto255.NewScalar().Multiply(lambda, s.signingShare)
	lambdaSC.Multiply(lambdaSC, challenge)
	z.Add(z, lambdaSC)

	return z.Bytes(), nil
}

// Aggregate combines the signature shares from a threshold of signers into a final FROST signature. The commitments
// must be the same set used during signing, and sigShares[i] must correspond to commitments[i] (after sorting by
// identifier). The resulting signature is a standard Schnorr signature verifiable with [Verify].
func Aggregate(domain string, groupKey *ristretto255.Element, message []byte, commitments []Commitment, sigShares [][]byte) ([]byte, error) {
	sorted := sortCommitments(commitments)

	if len(sorted) != len(sigShares) {
		return nil, ErrInvalidParameters
	}

	bindingFactors, err := computeBindingFactors(domain, groupKey, message, sorted)
	if err != nil {
		return nil, err
	}

	groupCommitment, err := computeGroupCommitment(sorted, bindingFactors)
	if err != nil {
		return nil, err
	}

	// Sum the signature shares: z = Σ z_i.
	z := ristretto255.NewScalar()
	for _, share := range sigShares {
		zi, _ := ristretto255.NewScalar().SetCanonicalBytes(share)
		if zi == nil {
			return nil, ErrInvalidShare
		}
		z.Add(z, zi)
	}

	return slices.Concat(groupCommitment.Bytes(), z.Bytes()), nil
}

// Verify checks a FROST signature against the group public key and message. FROST signatures are standard Schnorr
// signatures, so this function is compatible with signatures produced by [sig.Sign] and verifiable by [sig.Verify].
func Verify(domain string, groupKey *ristretto255.Element, message, signature []byte) bool {
	valid, _ := sig.Verify(domain, groupKey, signature, bytes.NewReader(message))
	return valid
}

// VerifyShare checks an individual signature share against the signer's verifying share. This can be used to identify
// which participant produced an invalid share before aggregation.
func VerifyShare(domain string, verifyingShare, groupKey *ristretto255.Element, identifier uint16, message []byte, commitments []Commitment, sigShare []byte) bool {
	sorted := sortCommitments(commitments)

	zi, _ := ristretto255.NewScalar().SetCanonicalBytes(sigShare)
	if zi == nil {
		return false
	}

	bindingFactors, err := computeBindingFactors(domain, groupKey, message, sorted)
	if err != nil {
		return false
	}

	rho, ok := bindingFactors[identifier]
	if !ok {
		return false
	}

	// Find this participant's commitment.
	var hiding, binding *ristretto255.Element
	for _, c := range sorted {
		if c.Identifier == identifier {
			hiding, _ = ristretto255.NewIdentityElement().SetCanonicalBytes(c.Hiding)
			binding, _ = ristretto255.NewIdentityElement().SetCanonicalBytes(c.Binding)

			break
		}
	}
	if hiding == nil || binding == nil {
		return false
	}

	groupCommitment, err := computeGroupCommitment(sorted, bindingFactors)
	if err != nil {
		return false
	}

	challenge := computeChallenge(domain, groupKey, message, groupCommitment)

	identifiers := make([]uint16, len(sorted))
	for i, c := range sorted {
		identifiers[i] = c.Identifier
	}
	lambda := lagrangeCoefficient(identifier, identifiers)

	// Verify: [z_i]G == D_i + [rho_i]E_i + [c * lambda_i]Y_i
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(zi)

	rhoE := ristretto255.NewIdentityElement().ScalarMult(rho, binding)
	commitPoint := ristretto255.NewIdentityElement().Add(hiding, rhoE)

	cLambda := ristretto255.NewScalar().Multiply(challenge, lambda)
	cLambdaY := ristretto255.NewIdentityElement().ScalarMult(cLambda, verifyingShare)

	expected := ristretto255.NewIdentityElement().Add(commitPoint, cLambdaY)

	return lhs.Equal(expected) == 1
}

// computeBindingFactors derives a binding factor for each participant from the unified transcript. Because the
// commitments are sorted by identifier (a total ordering), binding factors are derived independently using the same
// protocol state via cloning to align with the FROST security proof.
func computeBindingFactors(domain string, groupKey *ristretto255.Element, message []byte, commitments []Commitment) (map[uint16]*ristretto255.Scalar, error) {
	p := thyrse.New(domain)
	p.Mix("frost-binding", groupKey.Bytes())
	p.Mix("message", message)
	for _, c := range commitments {
		if len(c.Hiding) != 32 || len(c.Binding) != 32 {
			return nil, ErrInvalidCommitment
		}
		p.Mix("identifier", binary.BigEndian.AppendUint16(nil, c.Identifier))
		p.Mix("hiding", c.Hiding)
		p.Mix("binding", c.Binding)
	}

	factors := make(map[uint16]*ristretto255.Scalar, len(commitments))
	for _, c := range commitments {
		bp := p.Clone()
		bp.Mix("binding-participant", binary.BigEndian.AppendUint16(nil, c.Identifier))
		rho, _ := ristretto255.NewScalar().SetUniformBytes(bp.Derive("binding-factor", nil, 64))
		factors[c.Identifier] = rho
	}

	return factors, nil
}

// computeGroupCommitment computes the group commitment R = Σ(D_i + [rho_i]E_i).
func computeGroupCommitment(commitments []Commitment, bindingFactors map[uint16]*ristretto255.Scalar) (*ristretto255.Element, error) {
	result := ristretto255.NewIdentityElement()
	for _, c := range commitments {
		hiding, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(c.Hiding)
		binding, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(c.Binding)
		if hiding == nil || binding == nil {
			return nil, ErrInvalidCommitment
		}

		rho := bindingFactors[c.Identifier]
		rhoE := ristretto255.NewIdentityElement().ScalarMult(rho, binding)
		contribution := ristretto255.NewIdentityElement().Add(hiding, rhoE)
		result.Add(result, contribution)
	}

	return result, nil
}

// computeChallenge derives the Schnorr challenge scalar. The transcript matches [sig.Verify], ensuring compatibility.
func computeChallenge(domain string, groupKey *ristretto255.Element, message []byte, groupCommitment *ristretto255.Element) *ristretto255.Scalar {
	p := thyrse.New(domain)
	p.Mix("signer", groupKey.Bytes())
	_ = p.MixStream("message", bytes.NewReader(message))
	_, verifier := p.Fork("role", []byte("prover"), []byte("verifier"))
	verifier.Mix("commitment", groupCommitment.Bytes())
	c, _ := ristretto255.NewScalar().SetUniformBytes(verifier.Derive("challenge", nil, 64))

	return c
}

// evalPolynomial evaluates the polynomial f(x) = coeffs[0] + coeffs[1]*x + ... + coeffs[t-1]*x^(t-1) using Horner's
// method.
func evalPolynomial(coeffs []*ristretto255.Scalar, x uint16) *ristretto255.Scalar {
	xScalar := scalarFromUint16(x)
	n := len(coeffs)

	result, _ := ristretto255.NewScalar().SetCanonicalBytes(coeffs[n-1].Bytes())
	for i := n - 2; i >= 0; i-- {
		result.Multiply(result, xScalar)
		result.Add(result, coeffs[i])
	}

	return result
}

// lagrangeCoefficient computes the Lagrange interpolation coefficient for the given identifier at x=0.
// λ_i = Π_{j∈S, j≠i} (j / (j - i))
func lagrangeCoefficient(identifier uint16, identifiers []uint16) *ristretto255.Scalar {
	iScalar := scalarFromUint16(identifier)
	num := scalarFromUint16(1)
	den := scalarFromUint16(1)

	for _, j := range identifiers {
		if j == identifier {
			continue
		}
		jScalar := scalarFromUint16(j)
		num.Multiply(num, jScalar)

		negI := ristretto255.NewScalar().Negate(iScalar)
		diff := ristretto255.NewScalar().Add(jScalar, negI)
		den.Multiply(den, diff)
	}

	denInv := ristretto255.NewScalar().Invert(den)

	return ristretto255.NewScalar().Multiply(num, denInv)
}

// scalarFromUint16 creates a ristretto255 scalar from a uint16 value.
func scalarFromUint16(x uint16) *ristretto255.Scalar {
	var b [32]byte
	binary.LittleEndian.PutUint16(b[:], x)
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(b[:])

	return s
}

// sortCommitments returns a copy of the commitments sorted by identifier.
func sortCommitments(commitments []Commitment) []Commitment {
	sorted := slices.Clone(commitments)
	slices.SortFunc(sorted, func(a, b Commitment) int {
		return cmp.Compare(a.Identifier, b.Identifier)
	})

	return sorted
}

// validateCommitments checks for duplicate identifiers and verifies the signer is in the list.
func validateCommitments(sorted []Commitment, signerID uint16) error {
	found := false
	for i, c := range sorted {
		if c.Identifier == signerID {
			found = true
		}
		if i > 0 && sorted[i-1].Identifier == c.Identifier {
			return ErrDuplicateIdentifier
		}
	}
	if !found {
		return ErrMissingSigner
	}

	return nil
}
