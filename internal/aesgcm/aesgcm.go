// Package aesgcm implements one-shot AES-128-GCM with the ciphertext and tag
// returned separately, matching the split API this module previously used for
// TW128.
//
// Encrypt returns the ciphertext and authentication tag separately. Decrypt
// returns the (unverified) plaintext and the expected tag separately; the
// caller MUST compare the expected tag against the received tag in constant
// time and discard the plaintext on mismatch. This package never performs that
// comparison itself.
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

// Encrypt encrypts and authenticates plaintext under key and nonce, appending
// the ciphertext to dst. It returns the appended ciphertext and the
// authentication tag separately. The key must be KeySize bytes; a nil nonce is
// treated as NonceSize zero bytes.
func Encrypt(dst, key, nonce, plaintext []byte) (ciphertext, tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	return seal(dst, key, nonce, plaintext)
}

// Decrypt decrypts ciphertext under key and nonce, appending the unverified
// plaintext to dst. It returns the appended plaintext and the expected
// authentication tag separately. The caller must compare the expected tag
// against the received tag in constant time and discard the plaintext on
// mismatch. The key must be KeySize bytes; a nil nonce is treated as NonceSize
// zero bytes.
func Decrypt(dst, key, nonce, ciphertext []byte) (plaintext, tag []byte) {
	if len(key) != KeySize {
		panic("aesgcm: invalid key size")
	}
	return open(dst, key, nonce, ciphertext)
}

// sliceForAppend extends in by n bytes, returning the extended slice (head) and
// a slice aliasing just the appended region (tail). It allocates only if in
// lacks capacity.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
