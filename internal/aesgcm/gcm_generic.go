// The generic GCM and GHASH code in this file is adapted from the Go standard
// library's crypto/internal/fips140/aes/gcm package (gcm_generic.go and
// ghash.go), which carries the notice:
//
//	Copyright 2024 The Go Authors. All rights reserved.
//	Use of this source code is governed by a BSD-style license.
//
// The adaptations: the byteorder dependency is replaced with encoding/binary;
// AES-CTR is driven through crypto/cipher (which uses the optimized AES-CTR for
// crypto/aes); additional data is dropped; and seal/open return the ciphertext
// and tag (or unverified plaintext and expected tag) separately rather than as
// one appended buffer. This is the portable fallback used when the hardware
// AES-GCM assembly is unavailable.

package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
)

func sealGeneric(dst, key, nonce, plaintext []byte) (ciphertext, tag []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aesgcm: " + err.Error())
	}
	var H, counter, tagMask [gcmBlockSize]byte
	block.Encrypt(H[:], H[:]) // H = E_K(0)
	deriveCounterGeneric(&H, &counter, nonce)
	block.Encrypt(tagMask[:], counter[:]) // tagMask = E_K(J0)
	gcmInc32(&counter)                    // CTR starts at inc32(J0)

	ret, out := sliceForAppend(dst, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(out, plaintext)
	return ret, gcmAuthGeneric(&H, &tagMask, out)
}

func openGeneric(dst, key, nonce, ciphertext []byte) (plaintext, tag []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aesgcm: " + err.Error())
	}
	var H, counter, tagMask [gcmBlockSize]byte
	block.Encrypt(H[:], H[:])
	deriveCounterGeneric(&H, &counter, nonce)
	block.Encrypt(tagMask[:], counter[:])

	// Authenticate the ciphertext before it is overwritten in place.
	expectedTag := gcmAuthGeneric(&H, &tagMask, ciphertext)

	gcmInc32(&counter)
	ret, out := sliceForAppend(dst, len(ciphertext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(out, ciphertext)
	return ret, expectedTag
}

// deriveCounterGeneric computes the pre-counter block J0 (NIST SP 800-38D §7.1).
// A nil or 12-byte nonce uses the fast path; other lengths are hashed with
// GHASH. A nil nonce is treated as NonceSize zero bytes.
func deriveCounterGeneric(H *[gcmBlockSize]byte, counter *[gcmBlockSize]byte, nonce []byte) {
	if nonce == nil {
		nonce = zeroNonce[:]
	}
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
		return
	}
	var lenBlock [gcmBlockSize]byte
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(nonce))*8)
	ghash(counter, H, nonce, lenBlock[:])
}

// gcmInc32 increments the big-endian 32-bit counter in the final four bytes of
// the block, wrapping modulo 2^32 (GCM's counter increment).
func gcmInc32(counter *[gcmBlockSize]byte) {
	ctr := counter[len(counter)-4:]
	binary.BigEndian.PutUint32(ctr, binary.BigEndian.Uint32(ctr)+1)
}

// gcmAuthGeneric computes GHASH(ciphertext) (no additional data), masks it with
// tagMask, and returns the resulting tag.
func gcmAuthGeneric(H, tagMask *[gcmBlockSize]byte, ciphertext []byte) []byte {
	var lenBlock [gcmBlockSize]byte
	binary.BigEndian.PutUint64(lenBlock[8:], uint64(len(ciphertext))*8)
	var S [gcmBlockSize]byte
	ghash(&S, H, ciphertext, lenBlock[:])
	tag := make([]byte, gcmBlockSize)
	subtle.XORBytes(tag, S[:], tagMask[:])
	return tag
}

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make binary.BigEndian suitable for marshaling these values, the
// bits are stored in big endian order. For example:
//
//	the coefficient of x⁰ can be obtained by v.low >> 63.
//	the coefficient of x⁶³ can be obtained by v.low & 1.
//	the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//	the coefficient of x¹²⁷ can be obtained by v.high & 1.
type gcmFieldElement struct {
	low, high uint64
}

// ghash sets out to the GHASH of inputs under the key H. Each input is
// zero-padded to a multiple of the block size before being absorbed.
func ghash(out, H *[gcmBlockSize]byte, inputs ...[]byte) {
	// productTable contains the first sixteen powers of the key, H, in bit
	// reversed order. When we do lookups into this table we use bits from a
	// field element and therefore the bits are in reverse order, so e.g. 4*H
	// is at index 0010 (base 2) = 2.
	var productTable [16]gcmFieldElement
	x := gcmFieldElement{
		binary.BigEndian.Uint64(H[:8]),
		binary.BigEndian.Uint64(H[8:]),
	}
	productTable[reverseBits(1)] = x
	for i := 2; i < 16; i += 2 {
		productTable[reverseBits(i)] = ghashDouble(&productTable[reverseBits(i/2)])
		productTable[reverseBits(i+1)] = ghashAdd(&productTable[reverseBits(i)], &x)
	}

	var y gcmFieldElement
	for _, input := range inputs {
		ghashUpdate(&productTable, &y, input)
	}

	binary.BigEndian.PutUint64(out[:], y.low)
	binary.BigEndian.PutUint64(out[8:], y.high)
}

// reverseBits reverses the order of the bits of 4-bit number in i.
func reverseBits(i int) int {
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// ghashAdd adds two elements of GF(2¹²⁸) and returns the sum.
func ghashAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// ghashDouble returns the result of doubling an element of GF(2¹²⁸).
func ghashDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

var ghashReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// ghashMul sets y to y*H, where H is the GCM key, fixed during New.
func ghashMul(productTable *[16]gcmFieldElement, y *gcmFieldElement) {
	var z gcmFieldElement

	for i := range 2 {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(ghashReductionTable[msw]) << 48

			// the values in |table| are ordered for little-endian bit
			// positions. See the comment in New.
			t := productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
func updateBlocks(productTable *[16]gcmFieldElement, y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= binary.BigEndian.Uint64(blocks)
		y.high ^= binary.BigEndian.Uint64(blocks[8:])
		ghashMul(productTable, y)
		blocks = blocks[gcmBlockSize:]
	}
}

// ghashUpdate extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
func ghashUpdate(productTable *[16]gcmFieldElement, y *gcmFieldElement, data []byte) {
	fullBlocks := (len(data) >> 4) << 4
	updateBlocks(productTable, y, data[:fullBlocks])

	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		updateBlocks(productTable, y, partialBlock[:])
	}
}
