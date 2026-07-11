// Package hpke implements a hybrid public key encryption (HPKE) scheme.
//
// Messages are encrypted using a static-ephemeral Diffie-Hellman shared secret over Ristretto255 as the key. An
// authentication tag is appended to the end of the ciphertext, ensuring that the ciphertext can only be modified by
// someone in possession of either private key.
//
// In the signcryption model (which is suitable for analyzing confidentiality and authenticity in the public key model),
// this scheme is outsider-secure for both confidentiality and authenticity. No attacker only in possession of public
// keys can read plaintexts or forge ciphertexts. It is also insider-secure for confidentiality: an attacker who has
// the sender's private key but not the receiver's private key cannot read plaintexts. It is not, however,
// insider-secure for authenticity. An attacker in possession of the receiver's private key can forge messages from any
// sender whose public key they possess (aka Key Compromise Impersonation).
package hpke

import (
	"github.com/codahale/thyrse"
	"github.com/gtank/ristretto255"
)

// Overhead is the size, in bytes, of the additional data added to a message by Seal.
const Overhead = 32 + thyrse.TagSize

// Seal encrypts the given plaintext for the owner of the given public key, using the given sender's private key and
// user-provided random data.
//
// Panics if rand is not exactly 64 bytes or if a supplied or derived public key
// is the identity element.
func Seal(domain string, qR *ristretto255.Element, dS *ristretto255.Scalar, rand, plaintext []byte) []byte {
	if qR.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("hpke: receiver public key is identity")
	}
	qS := ristretto255.NewIdentityElement().ScalarBaseMult(dS)
	if qS.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("hpke: sender public key is identity")
	}

	// Generate an ephemeral key.
	dE, err := ristretto255.NewScalar().SetUniformBytes(rand)
	if err != nil {
		panic(err)
	}
	qE := ristretto255.NewIdentityElement().ScalarBaseMult(dE)
	if qE.Equal(ristretto255.NewIdentityElement()) == 1 {
		panic("hpke: ephemeral public key is identity")
	}

	// Calculate the ephemeral and static shared secrets.
	ssE := ristretto255.NewIdentityElement().ScalarMult(dE, qR)
	ssS := ristretto255.NewIdentityElement().ScalarMult(dS, qR)

	p := thyrse.New(domain)
	p.Mix("sender", qS.Bytes())
	p.Mix("receiver", qR.Bytes())
	p.Mix("ephemeral", qE.Bytes())
	p.Mix("ephemeral ecdh", ssE.Bytes())
	p.Mix("static ecdh", ssS.Bytes())
	return p.Seal("message", qE.Bytes(), plaintext)
}

// Open decrypts the ciphertext produced by Seal.
func Open(domain string, dR *ristretto255.Scalar, qS *ristretto255.Element, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}
	qR := ristretto255.NewIdentityElement().ScalarBaseMult(dR)
	identity := ristretto255.NewIdentityElement()
	if qR.Equal(identity) == 1 || qS.Equal(identity) == 1 {
		return nil, thyrse.ErrInvalidCiphertext
	}

	qE, _ := ristretto255.NewIdentityElement().SetCanonicalBytes(ciphertext[:32])
	if qE == nil || qE.Equal(identity) == 1 {
		return nil, thyrse.ErrInvalidCiphertext
	}
	ssE := ristretto255.NewIdentityElement().ScalarMult(dR, qE)
	ssS := ristretto255.NewIdentityElement().ScalarMult(dR, qS)

	p := thyrse.New(domain)
	p.Mix("sender", qS.Bytes())
	p.Mix("receiver", qR.Bytes())
	p.Mix("ephemeral", qE.Bytes())
	p.Mix("ephemeral ecdh", ssE.Bytes())
	p.Mix("static ecdh", ssS.Bytes())
	return p.Open("message", nil, ciphertext[32:])
}
