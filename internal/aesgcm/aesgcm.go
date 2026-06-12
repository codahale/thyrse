// Package aesgcm implements one-shot AES-128-CTR encryption authenticated with
// AES-128-GMAC over the ciphertext, with the ciphertext written to a
// caller-provided buffer and the authentication tag returned separately,
// matching the split API this module previously used for TW128.
//
// The construction is AES-GCM with the roles of the plaintext and the
// additional data swapped: the message is encrypted with the GCM keystream and
// the tag authenticates the ciphertext as additional data. Both halves are
// reproducible with the standard library. For a 12-byte (or nil) nonce the
// ciphertext equals AES-CTR (crypto/cipher.NewCTR) with the initial counter
// block nonce || 0x00000002, and the tag equals GMAC, i.e.
//
//	cipher.NewGCM(block).Seal(nil, nonce, nil, ciphertext)
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

	// maxMessageSize is the largest input Encrypt and Decrypt accept, the same
	// bound AES-GCM places on a plaintext. Beyond it the 32-bit GCM counter
	// would wrap and the keystream would no longer match the 128-bit-counter
	// AES-CTR of crypto/cipher.NewCTR.
	maxMessageSize = ((1 << 32) - 2) * gcmBlockSize
)

// zeroNonce is substituted for a nil nonce: a nil nonce is treated as NonceSize
// zero bytes, which is safe here because callers derive a fresh key per message.
var zeroNonce [gcmStandardNonceSize]byte

// Encrypt encrypts plaintext with AES-128-CTR under key and nonce, writing the
// ciphertext into dst, and returns the AES-128-GMAC tag over the ciphertext.
// dst must be exactly len(plaintext) bytes. The key must be KeySize bytes; a
// nil nonce is treated as NonceSize zero bytes.
func Encrypt(dst, key, nonce, plaintext []byte) (tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	if len(dst) != len(plaintext) {
		panic("aesgcm: output buffer must be len(plaintext) bytes")
	}
	if uint64(len(plaintext)) > maxMessageSize {
		panic("aesgcm: message too large")
	}
	return seal(dst, key, nonce, plaintext)
}

// Decrypt decrypts ciphertext with AES-128-CTR under key and nonce, writing the
// unverified plaintext into dst, and returns the expected AES-128-GMAC tag over
// the ciphertext. The caller must compare the expected tag against the received
// tag in constant time and discard the plaintext on mismatch. dst must be
// exactly len(ciphertext) bytes. The key must be KeySize bytes; a nil nonce is
// treated as NonceSize zero bytes.
func Decrypt(dst, key, nonce, ciphertext []byte) (tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	if len(dst) != len(ciphertext) {
		panic("aesgcm: output buffer must be len(ciphertext) bytes")
	}
	if uint64(len(ciphertext)) > maxMessageSize {
		panic("aesgcm: message too large")
	}
	return open(dst, key, nonce, ciphertext)
}
