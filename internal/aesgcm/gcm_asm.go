//go:build (amd64 || arm64) && !purego

package aesgcm

import "golang.org/x/sys/cpu"

// aes128Rounds is the AES-128 round count, passed to encryptBlockAsm.
const aes128Rounds = 10

// encryptBlockAsm encrypts a single AES block. It is defined in aes_amd64.s and
// aes_arm64.s (copied from the standard library) and reads the same key-schedule
// layout as the gcm assembly, so the tag mask E_K(J0) is computed from ks
// without a second key expansion.
//
//go:noescape
func encryptBlockAsm(nr int, xk *uint32, dst, src *byte)

// The following functions are defined in gcm_amd64.s and gcm_arm64.s, copied
// verbatim from the Go standard library. gcmAesInit builds the GHASH product
// table from the AES key schedule; gcmAesData folds data into the running tag
// (used here only for non-standard-nonce counter derivation); gcmAesEnc and
// gcmAesDec perform stitched AES-CTR + GHASH; gcmAesFinish absorbs the length
// block, masks with tagMask, and writes the tag.

//go:noescape
func gcmAesInit(productTable *[256]byte, ks []uint32)

//go:noescape
func gcmAesData(productTable *[256]byte, data []byte, T *[16]byte)

//go:noescape
func gcmAesEnc(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32)

//go:noescape
func gcmAesDec(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32)

//go:noescape
func gcmAesFinish(productTable *[256]byte, tagMask, T *[16]byte, pLen, dLen uint64)

// supportsGCM reports whether the stitched AES-GCM assembly may be used. It
// mirrors the feature set the assembly requires: AES + PCLMULQDQ (+ SSE4.1,
// SSSE3) on amd64, and AES + PMULL on arm64.
var supportsGCM = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ && cpu.X86.HasSSE41 && cpu.X86.HasSSSE3 ||
	cpu.ARM64.HasAES && cpu.ARM64.HasPMULL

func seal(dst, key, nonce, plaintext []byte) (ciphertext, tag []byte) {
	if !supportsGCM {
		return sealGeneric(dst, key, nonce, plaintext)
	}
	ks := expandKeyEnc(key)
	var productTable [256]byte
	gcmAesInit(&productTable, ks)

	var counter, tagMask, tagOut [gcmBlockSize]byte
	deriveCounterAsm(&productTable, &counter, nonce)
	encryptBlockAsm(aes128Rounds, &ks[0], &tagMask[0], &counter[0]) // tagMask = E_K(J0)

	ret, out := sliceForAppend(dst, len(plaintext))
	if len(plaintext) > 0 {
		gcmCrypt(gcmAesEnc, &productTable, out, plaintext, &counter, &tagOut, ks)
	}
	gcmAesFinish(&productTable, &tagMask, &tagOut, uint64(len(plaintext)), 0)

	tag = make([]byte, TagSize)
	copy(tag, tagOut[:])
	return ret, tag
}

func open(dst, key, nonce, ciphertext []byte) (plaintext, tag []byte) {
	if !supportsGCM {
		return openGeneric(dst, key, nonce, ciphertext)
	}
	ks := expandKeyEnc(key)
	var productTable [256]byte
	gcmAesInit(&productTable, ks)

	var counter, tagMask, tagOut [gcmBlockSize]byte
	deriveCounterAsm(&productTable, &counter, nonce)
	encryptBlockAsm(aes128Rounds, &ks[0], &tagMask[0], &counter[0]) // tagMask = E_K(J0)

	ret, out := sliceForAppend(dst, len(ciphertext))
	if len(ciphertext) > 0 {
		// gcmAesDec authenticates the ciphertext as it decrypts it.
		gcmCrypt(gcmAesDec, &productTable, out, ciphertext, &counter, &tagOut, ks)
	}
	gcmAesFinish(&productTable, &tagMask, &tagOut, uint64(len(ciphertext)), 0)

	tag = make([]byte, TagSize)
	copy(tag, tagOut[:])
	return ret, tag
}

// gcmCrypt runs fn (gcmAesEnc or gcmAesDec), which stores the final block of
// output as a full 16-byte write. When len(src) is not a whole number of
// blocks, that store would run past dst, so the operation is performed through a
// block-padded scratch buffer and only len(src) bytes are copied back.
func gcmCrypt(
	fn func(productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32),
	productTable *[256]byte, dst, src []byte, ctr, T *[16]byte, ks []uint32,
) {
	if len(src)%gcmBlockSize == 0 {
		fn(productTable, dst, src, ctr, T, ks)
		return
	}
	buf := make([]byte, (len(src)+gcmBlockSize-1)&^(gcmBlockSize-1))
	fn(productTable, buf, src, ctr, T, ks)
	copy(dst, buf)
	clear(buf)
}

// deriveCounterAsm computes the pre-counter block J0 into counter, which must be
// zeroed on entry. A nil or 12-byte nonce uses the fast path; other lengths are
// hashed with the hardware GHASH (NIST SP 800-38D §7.1).
func deriveCounterAsm(productTable *[256]byte, counter *[gcmBlockSize]byte, nonce []byte) {
	if nonce == nil {
		nonce = zeroNonce[:]
	}
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
		return
	}
	// J0 = GHASH(nonce-padded || 0^64 || [len(nonce)]_64). gcmAesData hashes the
	// nonce from a zero accumulator; gcmAesFinish appends the length block with a
	// zero tag mask, yielding J0.
	var zeroMask [gcmBlockSize]byte
	gcmAesData(productTable, nonce, counter)
	gcmAesFinish(productTable, &zeroMask, counter, uint64(len(nonce)), 0)
}
