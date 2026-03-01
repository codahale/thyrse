// Package siv implements a Synthetic Initialization Vector (SIV) AEAD scheme.
//
// This provides nonce-misuse resistant authenticated encryption (mrAE) and deterministic encryption (DAE) with a
// two-pass algorithm using a cloned protocol.
package siv

import (
	"crypto/cipher"
	"crypto/subtle"

	"github.com/codahale/thyrse"
)

// New returns a new cipher.AEAD instance which uses the given domain string and key.
//
// Panics if nonceSize is less than 16 bytes. A minimum of 16 bytes is required to ensure
// sufficient uniqueness and security for the nonce values.
func New(domain string, key []byte, nonceSize int) cipher.AEAD {
	if nonceSize < 16 {
		panic("thyrse/siv: nonce size must be at least 16 bytes")
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

// Seal encrypts and authenticates plaintext using the SIV mode, authenticates the additional
// data and appends the result to dst, returning the updated slice.
//
// Panics if len(nonce) != a.NonceSize(). The cipher.AEAD interface requires exact nonce sizes
// to prevent misuse that could compromise security.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("thyrse/siv: invalid nonce size")
	}

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)

	auth, conf := p.Fork("role", []byte("auth"), []byte("conf"))
	auth.Mix("message", plaintext)
	tag := auth.Derive("tag", nil, thyrse.TagSize)

	conf.Mix("tag", tag)

	return append(conf.Mask("message", dst, plaintext), tag...)
}

// Open decrypts and authenticates ciphertext using the SIV mode, authenticates the additional
// data and, if successful, appends the resulting plaintext to dst, returning the updated slice.
//
// Panics if len(nonce) != a.NonceSize(). The cipher.AEAD interface requires exact nonce sizes
// to prevent misuse that could compromise security.
func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("thyrse/siv: invalid nonce size")
	}

	if len(ciphertext) < thyrse.TagSize {
		return nil, thyrse.ErrInvalidCiphertext
	}

	ciphertext, receivedTag := ciphertext[:len(ciphertext)-thyrse.TagSize], ciphertext[len(ciphertext)-thyrse.TagSize:]

	p := a.p.Clone()
	p.Mix("nonce", nonce)
	p.Mix("ad", additionalData)

	auth, conf := p.Fork("role", []byte("auth"), []byte("conf"))

	conf.Mix("tag", receivedTag)

	ret := conf.Unmask("message", dst, ciphertext)
	plaintext := ret[len(dst):]

	auth.Mix("message", plaintext)
	expectedTag := auth.Derive("tag", nil, thyrse.TagSize)
	if subtle.ConstantTimeCompare(expectedTag, receivedTag) == 0 {
		clear(plaintext)
		return nil, thyrse.ErrInvalidCiphertext
	}

	return ret, nil
}

var _ cipher.AEAD = (*aead)(nil)
