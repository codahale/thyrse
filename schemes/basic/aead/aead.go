// Package aead provides an implementation of Authenticated Encryption with Associated Data (AEAD) using the Thyrse
// protocol.
package aead

import (
	"crypto/cipher"

	"github.com/codahale/thyrse"
)

// New returns a new cipher.AEAD instance which uses the given domain string and key.
//
// As with any AEAD, a nonce must never be repeated for the same key: encrypting two plaintexts under the same (key,
// nonce, additional data) triple reuses the keystream, revealing the XOR of the plaintexts (though, unlike
// polynomial-MAC AEADs, no authentication key). The 16-byte minimum makes randomly generated nonces safe within the
// 128-bit security level. Callers which cannot guarantee nonce uniqueness should use the misuse-resistant
// [github.com/codahale/thyrse/schemes/basic/siv] scheme instead.
//
// Panics if nonceSize is less than 16 bytes.
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
