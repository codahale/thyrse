// This file is the portable fallback used when the hardware AES-GCM assembly
// is unavailable. It is a two-pass composition of standard-library primitives:
// AES-CTR (crypto/cipher.NewCTR) produces the ciphertext, and a second pass
// computes the GMAC tag by sealing an empty plaintext with the ciphertext as
// additional data under crypto/cipher's AES-GCM.

package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
)

func sealGeneric(dst, key, nonce, plaintext []byte) (tag []byte) {
	if nonce == nil {
		nonce = zeroNonce[:]
	}
	block, aead := newGeneric(key, len(nonce))
	ctrGeneric(block, aead, nonce, dst, plaintext)
	return aead.Seal(nil, nonce, nil, dst)
}

func openGeneric(dst, key, nonce, ciphertext []byte) (tag []byte) {
	if nonce == nil {
		nonce = zeroNonce[:]
	}
	block, aead := newGeneric(key, len(nonce))
	// Authenticate the ciphertext before it is overwritten, in case dst aliases it.
	tag = aead.Seal(nil, nonce, nil, ciphertext)
	ctrGeneric(block, aead, nonce, dst, ciphertext)
	return tag
}

// newGeneric builds the AES block cipher and the GCM AEAD used for the GMAC
// pass (and, for non-standard nonce lengths, the CTR pass).
func newGeneric(key []byte, nonceSize int) (cipher.Block, cipher.AEAD) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aesgcm: " + err.Error())
	}
	var aead cipher.AEAD
	if nonceSize == gcmStandardNonceSize {
		aead, err = cipher.NewGCM(block)
	} else {
		aead, err = cipher.NewGCMWithNonceSize(block, nonceSize)
	}
	if err != nil {
		panic("aesgcm: " + err.Error())
	}
	return block, aead
}

// ctrGeneric applies the AES-CTR keystream GCM uses, starting at inc32(J0),
// XORing src into dst. dst and src may be the same slice.
func ctrGeneric(block cipher.Block, aead cipher.AEAD, nonce, dst, src []byte) {
	if len(nonce) == gcmStandardNonceSize {
		// J0 = nonce || 0x00000001, so the stream starts at nonce || 0x00000002.
		var iv [gcmBlockSize]byte
		copy(iv[:], nonce)
		iv[gcmBlockSize-1] = 2
		cipher.NewCTR(block, iv[:]).XORKeyStream(dst, src)
		return
	}
	// For other nonce lengths J0 is GHASH-derived and cannot be reconstructed
	// from standard-library primitives, so use GCM itself as the CTR engine:
	// the ciphertext half of a seal is exactly the keystream XOR. The tag it
	// appends is discarded.
	out := aead.Seal(make([]byte, 0, len(src)+TagSize), nonce, src, nil)
	copy(dst, out[:len(src)])
	clear(out)
}
