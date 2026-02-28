// Package aead provides an implementation of Authenticated Encryption with Associated Data (AEAD) using the thyrse
// protocol.
package aead

import (
	"crypto/cipher"

	"github.com/codahale/thyrse"
)

// New returns a new cipher.AEAD instance which uses the given domain string and key.
//
// Panics if nonceSize is less than 16 bytes. A minimum of 16 bytes is required to ensure
// sufficient uniqueness and security for the nonce values.
func New(domain string, key []byte, nonceSize int) cipher.AEAD {
	if nonceSize < 16 {
		panic("thyrse/aead: nonce size must be at least 16 bytes")
	}
	p := thyrse.New(domain)
	p.Mix("key", key)
	return &aead{
		p:         p,
		nonceSize: nonceSize,
	}
}

type aead struct {
	p         *thyrse.Protocol
	nonceSize int
}

func (a *aead) NonceSize() int {
	return a.nonceSize
}

func (a *aead) Overhead() int {
	return thyrse.TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the additional data and appends
// the result to dst, returning the updated slice.
//
// Panics if len(nonce) != a.NonceSize(). The cipher.AEAD interface requires exact nonce sizes
// to prevent misuse that could compromise security.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("thyrse/aead: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)
	return p.Seal("message", dst, plaintext)
}

// Open decrypts and authenticates ciphertext, authenticates the additional data and, if successful,
// appends the resulting plaintext to dst, returning the updated slice.
//
// Panics if len(nonce) != a.NonceSize(). The cipher.AEAD interface requires exact nonce sizes
// to prevent misuse that could compromise security.
func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("thyrse/aead: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)
	return p.Open("message", dst, ciphertext)
}

var _ cipher.AEAD = (*aead)(nil)
