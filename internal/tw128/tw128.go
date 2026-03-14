// Package tw128 implements TW128, a tree-parallel authenticated encryption algorithm that uses a Sakura flat-tree
// topology with kangaroo hopping to enable SIMD acceleration on large inputs.
//
// Each tree node absorbs encode_string(K) || encode_string(N) || encode_string(AD) || LEU64(i) into a duplex,
// pad-permutes with 0x08, and encrypts. The context prefix is absorbed once into a "base" duplex state, then
// cloned per node.
//
// The final node (index 0) encrypts chunk 0 directly (the "message hop"). For multi-chunk messages, independent leaves
// (indices 1..n-1) encrypt subsequent chunks and produce chain values that are absorbed into the final node (the
// "chaining hop"). All leaf operations are independent and executed in parallel using SIMD-accelerated permutations.
package tw128

import (
	"encoding/binary"

	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each leaf chunk in bytes.
	ChunkSize = 8 * 1024

	initDS       = 0x08 // Domain separation byte for duplex init (prefix+index absorption).
	chainValueDS = 0x0B // Domain separation byte for chain value (Sakura inner node '110').
	tagSingleDS  = 0x07 // Domain separation byte for tag, n=1 (Sakura single-node final '11').
	tagChainDS   = 0x06 // Domain separation byte for tag, n>1 (Sakura chaining-hop final '01').
)

// hopFrame is the Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first (8 bytes).
var hopFrame = [8]byte{0x03}

// initBase absorbs encode_string(key) || encode_string(nonce) || encode_string(ad) into a fresh state.
// AD is absorbed as header+body to avoid copying large AD.
func initBase(base *keccak.State1, key, nonce, ad []byte) {
	base.Reset()

	// K and N are small, so batch them.
	var buf [128]byte
	b := buf[:0]
	b = enc.EncodeString(b, key)
	b = enc.EncodeString(b, nonce)
	base.Absorb(b)

	// AD may be large — encode header separately, then stream AD data.
	b = buf[:0]
	b = enc.LeftEncode(b, uint64(len(ad))*8)
	base.Absorb(b)
	base.Absorb(ad)
}

// initNode clones base, absorbs LEU64(index), and pad-permutes with initDS.
func initNode(d *keccak.State1, base *keccak.State1, index uint64) {
	*d = base.Clone()
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], index)
	d.Absorb(idx[:])
	d.PadPermute(initDS)
}

type cryptor struct {
	base      keccak.State1 // base state with prefix absorbed
	leaf      keccak.State1 // current leaf's state (for chunks 1+)
	final     keccak.State1 // final node state (encrypts chunk 0, absorbs CVs)
	finalized bool
	nLeaves   int  // number of completed leaf CVs absorbed into final node
	chunkOff  int  // bytes processed in current chunk
	leafMode  bool // true after chunk 0 complete and HOP_FRAME absorbed
}

// finalizeCV squeezes the chain value from the current leaf's state and absorbs it into the final node.
func (c *cryptor) finalizeCV() {
	c.leaf.PadPermute(chainValueDS)
	var cv [KeySize]byte
	c.leaf.Squeeze(cv[:])
	c.final.Absorb(cv[:])
	c.nLeaves++
	c.chunkOff = 0
}

// transitionToLeafMode absorbs HOP_FRAME into the final node and enters leaf mode.
func (c *cryptor) transitionToLeafMode() {
	c.final.Absorb(hopFrame[:])
	c.leafMode = true
	c.chunkOff = 0
}

func (c *cryptor) finalizeInternal() [TagSize]byte {
	if c.finalized {
		panic("tw128: Finalize called more than once")
	}
	c.finalized = true

	if !c.leafMode {
		// n=1: tag directly from final node (which encrypted chunk 0).
		c.final.PadPermute(tagSingleDS)
		var tag [TagSize]byte
		c.final.Squeeze(tag[:])
		return tag
	}

	// n>1: finalize last leaf if partial chunk in progress.
	if c.chunkOff > 0 {
		c.finalizeCV()
	}

	// Chaining hop suffix: length_encode(nLeaves) || 0xFF || 0xFF
	var leBuf [9 + 2]byte
	suffix := append(enc.LengthEncode(leBuf[:0], uint64(c.nLeaves)), 0xFF, 0xFF)
	c.final.Absorb(suffix)

	// Tag: pad_permute(0x06)
	c.final.PadPermute(tagChainDS)
	var tag [TagSize]byte
	c.final.Squeeze(tag[:])
	return tag
}

// Encryptor incrementally encrypts data and computes the authentication tag. It implements a streaming interface where
// each call to [Encryptor.XORKeyStream] immediately produces ciphertext. Call [Encryptor.Finalize] after all data has
// been processed to obtain the authentication tag.
type Encryptor struct {
	cryptor
}

// NewEncryptor returns a new Encryptor initialized with the given key, nonce, and associated data.
func NewEncryptor(key, nonce, ad []byte) (e Encryptor) {
	initBase(&e.base, key, nonce, ad)
	initNode(&e.final, &e.base, 0)
	return e
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (e *Encryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !e.leafMode {
		// Still on chunk 0: encrypt into final node.
		n := min(len(src), ChunkSize-e.chunkOff)
		e.final.Encrypt(dst[:n], src[:n])
		e.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if e.chunkOff == ChunkSize && len(src) > 0 {
			e.transitionToLeafMode()
		}

		if len(src) == 0 {
			return
		}
	}

	// Leaf mode: processing chunks 1..n-1.

	// Continue an in-progress partial leaf chunk.
	if e.chunkOff > 0 {
		n := min(len(src), ChunkSize-e.chunkOff)
		e.leaf.Encrypt(dst[:n], src[:n])
		e.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if e.chunkOff == ChunkSize {
			e.finalizeCV()
		}
	}

	// Process complete leaf chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		e.encryptComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial leaf chunk with remaining bytes.
	if len(src) > 0 {
		initNode(&e.leaf, &e.base, uint64(e.nLeaves+1))
		e.chunkOff = 0
		e.leaf.Encrypt(dst[:len(src)], src)
		e.chunkOff += len(src)
	}
}

// encryptComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (e *Encryptor) encryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var cvs [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		keccak.EncryptChunksTW128(&e.base, uint64(e.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &cvs)
		e.final.AbsorbCVs(cvs[:])
		e.nLeaves += 8
		idx += 8
	}

	// Remainder: pad to 8 and use x8 when utilization is high enough to
	// offset the cost of absorbing+permuting unused padding lanes.
	if rem := nFlush - idx; rem >= 5 {
		off := idx * ChunkSize
		realBytes := rem * ChunkSize
		var padSrc, padDst [8 * ChunkSize]byte
		copy(padSrc[:realBytes], src[off:off+realBytes])
		keccak.EncryptChunksTW128(&e.base, uint64(e.nLeaves+1), padSrc[:], padDst[:], &cvs)
		copy(dst[off:off+realBytes], padDst[:realBytes])
		e.final.AbsorbCVs(cvs[:rem*32])
		e.nLeaves += rem
		idx += rem
	}

	// Small remainder via x1.
	for idx < nFlush {
		off := idx * ChunkSize
		var d keccak.State1
		encryptX1(&e.base, uint64(e.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &d)
		e.final.AbsorbCV(&d)
		e.nLeaves++
		idx++
	}
}

// Finalize returns the authentication tag. It must be called exactly once after all data has been processed via
// [Encryptor.XORKeyStream].
func (e *Encryptor) Finalize() [TagSize]byte {
	return e.finalizeInternal()
}

// Decryptor incrementally decrypts data and computes the authentication tag. It implements a streaming interface where
// each call to [Decryptor.XORKeyStream] immediately produces plaintext. Call [Decryptor.Finalize] after all data has
// been processed to obtain the expected authentication tag. The caller MUST verify the tag using constant-time
// comparison before using the plaintext.
type Decryptor struct {
	cryptor
}

// NewDecryptor returns a new Decryptor initialized with the given key, nonce, and associated data.
func NewDecryptor(key, nonce, ad []byte) (d Decryptor) {
	initBase(&d.base, key, nonce, ad)
	initNode(&d.final, &d.base, 0)
	return d
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (d *Decryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !d.leafMode {
		// Still on chunk 0: decrypt from final node.
		n := min(len(src), ChunkSize-d.chunkOff)
		d.final.Decrypt(dst[:n], src[:n])
		d.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if d.chunkOff == ChunkSize && len(src) > 0 {
			d.transitionToLeafMode()
		}

		if len(src) == 0 {
			return
		}
	}

	// Leaf mode: processing chunks 1..n-1.

	// Continue an in-progress partial leaf chunk.
	if d.chunkOff > 0 {
		n := min(len(src), ChunkSize-d.chunkOff)
		d.leaf.Decrypt(dst[:n], src[:n])
		d.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if d.chunkOff == ChunkSize {
			d.finalizeCV()
		}
	}

	// Process complete leaf chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		d.decryptComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial leaf chunk with remaining bytes.
	if len(src) > 0 {
		initNode(&d.leaf, &d.base, uint64(d.nLeaves+1))
		d.chunkOff = 0
		d.leaf.Decrypt(dst[:len(src)], src)
		d.chunkOff += len(src)
	}
}

// decryptComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (d *Decryptor) decryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var cvs [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		keccak.DecryptChunksTW128(&d.base, uint64(d.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &cvs)
		d.final.AbsorbCVs(cvs[:])
		d.nLeaves += 8
		idx += 8
	}

	// Remainder: pad to 8 and use x8 when utilization is high enough to
	// offset the cost of absorbing+permuting unused padding lanes.
	if rem := nFlush - idx; rem >= 5 {
		off := idx * ChunkSize
		realBytes := rem * ChunkSize
		var padSrc, padDst [8 * ChunkSize]byte
		copy(padSrc[:realBytes], src[off:off+realBytes])
		keccak.DecryptChunksTW128(&d.base, uint64(d.nLeaves+1), padSrc[:], padDst[:], &cvs)
		copy(dst[off:off+realBytes], padDst[:realBytes])
		d.final.AbsorbCVs(cvs[:rem*32])
		d.nLeaves += rem
		idx += rem
	}

	// Small remainder via x1.
	for idx < nFlush {
		off := idx * ChunkSize
		var leaf keccak.State1
		decryptX1(&d.base, uint64(d.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &leaf)
		d.final.AbsorbCV(&leaf)
		d.nLeaves++
		idx++
	}
}

// Finalize returns the expected authentication tag. It must be called exactly once after all data has been processed
// via [Decryptor.XORKeyStream]. The caller MUST verify the tag using constant-time comparison before using the
// plaintext.
func (d *Decryptor) Finalize() [TagSize]byte {
	return d.finalizeInternal()
}

func encryptX1(base *keccak.State1, index uint64, pt, ct []byte, d *keccak.State1) {
	initNode(d, base, index)
	d.EncryptAll(pt, ct, chainValueDS)
}

func decryptX1(base *keccak.State1, index uint64, ct, pt []byte, d *keccak.State1) {
	initNode(d, base, index)
	d.DecryptAll(ct, pt, chainValueDS)
}
