// Package signcrypt implements an integrated signcryption scheme using Ristretto255 and Thyrse.
package signcrypt

import (
	"crypto/subtle"

	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// Overhead is the length, in bytes, of the additional data added to a plaintext to produce a signcrypted ciphertext.
const Overhead = 32 + 32 + 32

// Seal encrypts and signs the message to protect its confidentiality and authenticity. Only the owner of the
// receiver's private key can decrypt it, and only the owner of the sender's private key could have sent it.
func Seal(domain string, dS *ristretto255.Scalar, qR *ristretto255.Element, rand, message []byte) []byte {
	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := thyrse.New(domain)
	p.Mix("receiver", qR.Bytes())
	p.Mix("sender", ristretto255.NewIdentityElement().ScalarBaseMult(dS).Bytes())

	// Fork the protocol into sender and receiver roles.
	sender, receiver := p.Fork("role", []byte("sender"), []byte("receiver"))

	// Mix the sender's private key, the user-supplied randomness, and the message into the sender. Use the sender to
	// derive an ephemeral private key and commitment scalar which are unique to the inputs.
	sender.Mix("sender-private", dS.Bytes())
	sender.Mix("rand", rand)
	sender.Mix("message", message)
	dE, _ := ristretto255.NewScalar().SetUniformBytes(sender.Derive("ephemeral-private", nil, 64))
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	k, _ := ristretto255.NewScalar().SetUniformBytes(sender.Derive("commitment", nil, 64))
	r := ristretto255.NewIdentityElement().ScalarBaseMult(k)

	// Mix the ephemeral public key and ECDH shared secret into the receiver.
	receiver.Mix("ephemeral", qE.Bytes())
	receiver.Mix("ecdh", ristretto255.NewIdentityElement().ScalarMult(dE, qR).Bytes())

	// Mask the message.
	ciphertext := receiver.Mask("message", qE.Bytes(), message)

	// Mask the commitment point. This provides signer confidentiality (unless the verifier has both the signer's
	// public key and the message) and makes the protocol's state dependent on the commitment.
	sig := receiver.Mask("commitment", ciphertext, r.Bytes())

	// Derive a challenge scalar from the signer's public key, the message, and the commitment point.
	c, _ := ristretto255.NewScalar().SetUniformBytes(receiver.Derive("challenge", nil, 64))

	// Calculate the proof scalar s = k + d*c and mask it.
	s := ristretto255.NewScalar().Multiply(dS, c)
	s = s.Add(s, k)
	return receiver.Mask("proof", sig, s.Bytes())
}

// Open decrypts and verifies a ciphertext produced by Seal. Returns either the confidential, authentic plaintext or
// thyrse.ErrInvalidCiphertext.
func Open(domain string, dR *ristretto255.Scalar, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}

	// Initialize the protocol and mix in the sender and receiver's public keys.
	p := thyrse.New(domain)
	p.Mix("receiver", ristretto255.NewIdentityElement().ScalarBaseMult(dR).Bytes())
	p.Mix("sender", qS.Bytes())

	// Fork the protocol into sender and receiver roles.
	_, receiver := p.Fork("role", []byte("sender"), []byte("receiver"))

	// Mix in the ephemeral public key and decode it.
	receiver.Mix("ephemeral", ciphertext[:32])
	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(ciphertext[:32])
	if qE == nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	// Mix in the ECDH shared secret.
	receiver.Mix("ecdh", ristretto255.NewIdentityElement().ScalarMult(dR, qE).Bytes())

	// Unmask the message.
	plaintext := receiver.Unmask("message", nil, ciphertext[32:len(ciphertext)-64])

	// Unmask the received commitment point. As we do not use it for calculations, leave it encoded.
	receivedR := receiver.Unmask("commitment", nil, ciphertext[len(ciphertext)-64:len(ciphertext)-32])

	// Derive an expected challenge scalar from the signer's public key, the message, and the commitment point.
	expectedC, _ := ristretto255.NewScalar().SetUniformBytes(receiver.Derive("challenge", nil, 64))

	// Unmask the proof scalar. If not canonically encoded, the signature is invalid.
	s, _ := ristretto255.NewScalar().SetCanonicalBytes(receiver.Unmask("proof", nil, ciphertext[len(ciphertext)-32:]))
	if s == nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	// Calculate the expected commitment point: R' = [s]G + [-c']Q
	expectedR := ristretto255.NewIdentityElement().ScalarBaseMult(s)
	expectedR.Add(expectedR, ristretto255.NewIdentityElement().ScalarMult(ristretto255.NewScalar().Negate(expectedC), qS))

	// If the received and expected commitment points are equal (as compared in their encoded forms), the signature is
	// valid.
	if subtle.ConstantTimeCompare(receivedR, expectedR.Bytes()) == 0 {
		return nil, thyrse.ErrInvalidCiphertext
	}

	return plaintext, nil
}
