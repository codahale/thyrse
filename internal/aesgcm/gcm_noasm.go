//go:build !((amd64 || arm64) && !purego)

package aesgcm

// On platforms without the stitched AES-GCM assembly (or under the purego build
// tag), seal and open use the portable implementation.

func seal(dst, key, nonce, plaintext []byte) (tag []byte) {
	return sealGeneric(dst, key, nonce, plaintext)
}

func open(dst, key, nonce, ciphertext []byte) (tag []byte) {
	return openGeneric(dst, key, nonce, ciphertext)
}
