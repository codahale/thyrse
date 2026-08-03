// Package hpke implements anonymous hybrid public key encryption using X25519 and ML-KEM-768.
//
// Seal generates a fresh X25519 key and ML-KEM encapsulation for each message. The resulting shared secrets are
// combined in a Thyrse transcript and used to encrypt and authenticate the plaintext. The scheme authenticates the
// ciphertext, not its sender: anyone with the receiver's public keys can create a valid ciphertext.
package hpke

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"

	"github.com/codahale/thyrse"
)

const (
	x25519PublicKeySize = 32
	headerSize          = x25519PublicKeySize + mlkem.CiphertextSize768

	// Overhead is the size, in bytes, of the additional data added to a message by Seal.
	Overhead = headerSize + thyrse.TagSize
)

// Seal encrypts plaintext for the owners of the receiver's X25519 and ML-KEM public keys.
//
// Panics if the X25519 public key produces an invalid shared secret.
func Seal(
	domain string,
	receiver *ecdh.PublicKey,
	receiverKEM *mlkem.EncapsulationKey768,
	plaintext []byte,
) []byte {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ephemeralPublic := ephemeral.PublicKey()

	x25519Shared, err := ephemeral.ECDH(receiver)
	if err != nil {
		panic("hpke: invalid X25519 receiver public key")
	}
	mlkemShared, mlkemCiphertext := receiverKEM.Encapsulate()

	header := make([]byte, headerSize)
	copy(header[:x25519PublicKeySize], ephemeralPublic.Bytes())
	copy(header[x25519PublicKeySize:], mlkemCiphertext)

	p := newProtocol(
		domain,
		receiver,
		receiverKEM,
		ephemeralPublic,
		mlkemCiphertext,
		x25519Shared,
		mlkemShared,
	)
	return p.Seal("message", header, plaintext)
}

// Open decrypts a ciphertext produced by Seal using the receiver's X25519 and ML-KEM private keys.
func Open(
	domain string,
	receiver *ecdh.PrivateKey,
	receiverKEM *mlkem.DecapsulationKey768,
	ciphertext []byte,
) ([]byte, error) {
	if len(ciphertext) < Overhead {
		return nil, thyrse.ErrInvalidCiphertext
	}

	header := ciphertext[:headerSize]
	ephemeralPublic, err := ecdh.X25519().NewPublicKey(header[:x25519PublicKeySize])
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}
	x25519Shared, err := receiver.ECDH(ephemeralPublic)
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	mlkemCiphertext := header[x25519PublicKeySize:]
	mlkemShared, err := receiverKEM.Decapsulate(mlkemCiphertext)
	if err != nil {
		return nil, thyrse.ErrInvalidCiphertext
	}

	p := newProtocol(
		domain,
		receiver.PublicKey(),
		receiverKEM.EncapsulationKey(),
		ephemeralPublic,
		mlkemCiphertext,
		x25519Shared,
		mlkemShared,
	)
	return p.Open("message", nil, ciphertext[headerSize:])
}

func newProtocol(
	domain string,
	receiver *ecdh.PublicKey,
	receiverKEM *mlkem.EncapsulationKey768,
	ephemeral *ecdh.PublicKey,
	mlkemCiphertext, x25519Shared, mlkemShared []byte,
) *thyrse.Protocol {
	p := thyrse.New(domain)
	p.Mix("receiver x25519", receiver.Bytes())
	p.Mix("receiver ml-kem", receiverKEM.Bytes())
	p.Mix("ephemeral x25519", ephemeral.Bytes())
	p.Mix("ml-kem ciphertext", mlkemCiphertext)
	p.Mix("x25519 shared secret", x25519Shared)
	p.Mix("ml-kem shared secret", mlkemShared)
	return p
}
