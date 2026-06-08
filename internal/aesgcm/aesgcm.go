// Package aesgcm implements one-shot AES-128-GCM with the ciphertext written to
// a caller-provided buffer and the authentication tag returned separately,
// matching the split API this module previously used for TW128.
//
// Encrypt writes the ciphertext into dst and returns the authentication tag.
// Decrypt writes the (unverified) plaintext into dst and returns the expected
// tag; the caller MUST compare the expected tag against the received tag in
// constant time and discard the plaintext on mismatch. This package never
// performs that comparison itself. In both cases dst must be exactly as long as
// the input.
//
// Only AES-128 (16-byte keys) is supported. On amd64 and arm64 the stitched
// AES-CTR+GHASH assembly from the Go standard library is used (AES-NI/PMULL +
// PCLMULQDQ/PMULL); other platforms, and CPUs without those extensions, fall
// back to a portable implementation built on crypto/aes and crypto/cipher.
package aesgcm

const (
	// KeySize is the AES-128 key size in bytes.
	KeySize = 16

	// NonceSize is the standard GCM nonce size in bytes.
	NonceSize = 12

	// TagSize is the GCM authentication tag size in bytes.
	TagSize = 16

	// gcmBlockSize is the AES and GCM block size in bytes.
	gcmBlockSize = 16

	// gcmStandardNonceSize is the nonce length that uses the fast counter path.
	gcmStandardNonceSize = 12
)

// zeroNonce is substituted for a nil nonce: a nil nonce is treated as NonceSize
// zero bytes, which is safe here because callers derive a fresh key per message.
var zeroNonce [gcmStandardNonceSize]byte

// Encrypt encrypts and authenticates plaintext under key and nonce, writing the
// ciphertext into dst and returning the authentication tag. dst must be exactly
// len(plaintext) bytes. The key must be KeySize bytes; a nil nonce is treated as
// NonceSize zero bytes.
func Encrypt(dst, key, nonce, plaintext []byte) (tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	if len(dst) != len(plaintext) {
		panic("aesgcm: output buffer must be len(plaintext) bytes")
	}
	return seal(dst, key, nonce, plaintext)
}

// Decrypt decrypts ciphertext under key and nonce, writing the unverified
// plaintext into dst and returning the expected authentication tag. The caller
// must compare the expected tag against the received tag in constant time and
// discard the plaintext on mismatch. dst must be exactly len(ciphertext) bytes.
// The key must be KeySize bytes; a nil nonce is treated as NonceSize zero bytes.
func Decrypt(dst, key, nonce, ciphertext []byte) (tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	if len(dst) != len(ciphertext) {
		panic("aesgcm: output buffer must be len(ciphertext) bytes")
	}
	return open(dst, key, nonce, ciphertext)
}
