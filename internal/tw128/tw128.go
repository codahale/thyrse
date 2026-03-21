// Package tw128 implements TW128, a tree-parallel authenticated encryption algorithm based on keyed duplexes.
//
// The trunk duplex handles optional associated-data absorption, encryption of chunk 0, optional absorption
// of later hidden leaf tags, and squeezing the final authentication tag. Later chunks are processed by
// independent LeafWrap transcripts under disjoint IVs iv(U, i) for i >= 1.
//
// Each duplex is initialized with S = K || iv(U, j) and operates with pad10* padding and per-block capacity
// framing (body blocks are full-state: block || 0x01 || 0^{c-1}).
package tw128

import (
	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// NonceSize is the size of the nonce in bytes.
	NonceSize = 16

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each chunk in bytes.
	ChunkSize = 8128

	// leafTagSize is the size of each hidden leaf tag in bytes.
	leafTagSize = 32

	// trailerAD is the phase trailer for the associated-data phase.
	trailerAD = 0x00

	// trailerTC is the phase trailer for the leaf-tag (tag-chain) phase.
	trailerTC = 0x01
)

// iv computes the IV for duplex index j: 0^{168-16-|ν(j)|} || nonce || ν(j).
// Nonce must be NonceSize bytes (or nil, treated as all zeros).
func iv(nonce []byte, j uint64) [keccak.Rate]byte {
	var buf [keccak.Rate]byte
	var nu [enc.MaxIntSize + 1]byte
	nuSlice := enc.RightEncode(nu[:0], j)
	off := keccak.Rate - NonceSize - len(nuSlice)
	copy(buf[off:], nonce)
	copy(buf[off+NonceSize:], nuSlice)
	return buf
}

// initTrunk initializes a trunk duplex with K, iv(U,0), and optional AD absorption.
func initTrunk(s *keccak.State1, key, nonce, ad []byte) {
	ivBuf := iv(nonce, 0)
	s.InitKeyed(key, ivBuf[:])
	if len(ad) > 0 {
		s.Absorb(ad)
		s.Absorb([]byte{trailerAD})
		s.PadStarPermute()
	}
}

// initLeaf initializes a leaf duplex with K, iv(U,j).
func initLeaf(s *keccak.State1, key, nonce []byte, j uint64) {
	ivBuf := iv(nonce, j)
	s.InitKeyed(key, ivBuf[:])
}

type cryptor struct {
	key       [KeySize]byte
	nonce     [NonceSize]byte
	trunk     keccak.State1 // trunk duplex state
	leaf      keccak.State1 // current leaf duplex state (chunks 1+)
	nLeaves   int           // number of completed leaves
	chunkOff  int           // bytes processed in current chunk
	leafMode  bool          // true after chunk 0 body complete
	finalized bool
}

func (c *cryptor) initCryptor(key, nonce, ad []byte) {
	copy(c.key[:], key)
	if len(nonce) > 0 {
		copy(c.nonce[:], nonce)
	}
	initTrunk(&c.trunk, c.key[:], c.nonce[:], ad)
}

// finalizeLeaf squeezes the current leaf's tag and absorbs it into the trunk.
// Uses AbsorbCV to read directly from the leaf's lane-major state, avoiding
// byte serialization.
func (c *cryptor) finalizeLeaf() {
	c.leaf.BodyPadStarPermute()
	c.trunk.AbsorbCV(&c.leaf)
	c.nLeaves++
	c.chunkOff = 0
}

// transitionToLeafMode finalizes the trunk body phase and enters leaf mode.
func (c *cryptor) transitionToLeafMode() {
	c.trunk.BodyPadStarPermute()
	c.leafMode = true
	c.chunkOff = 0
}

func (c *cryptor) finalizeInternal() [TagSize]byte {
	if c.finalized {
		panic("tw128: Finalize called more than once")
	}
	c.finalized = true

	// If still on chunk 0 and body data was written, finalize the trunk body phase.
	if !c.leafMode && c.chunkOff > 0 {
		c.trunk.BodyPadStarPermute()
	}

	// Finalize the last leaf if a partial chunk is in progress.
	if c.leafMode && c.chunkOff > 0 {
		c.finalizeLeaf()
	}

	// Tag-absorb phase: leaf tags were absorbed incrementally; finalize with trailer.
	if c.nLeaves > 0 {
		c.trunk.Absorb([]byte{trailerTC})
		c.trunk.PadStarPermute()
	}

	var tag [TagSize]byte
	c.trunk.Squeeze(tag[:])
	return tag
}

// Encryptor incrementally encrypts data and computes the authentication tag.
type Encryptor struct {
	cryptor
}

// NewEncryptor returns a new Encryptor initialized with the given key, nonce, and associated data.
func NewEncryptor(key, nonce, ad []byte) (e Encryptor) {
	e.initCryptor(key, nonce, ad)
	return e
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (e *Encryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !e.leafMode {
		// Still on chunk 0: encrypt into trunk.
		n := min(len(src), ChunkSize-e.chunkOff)
		e.trunk.BodyEncrypt(dst[:n], src[:n])
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
		e.leaf.BodyEncrypt(dst[:n], src[:n])
		e.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if e.chunkOff == ChunkSize {
			e.finalizeLeaf()
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
		initLeaf(&e.leaf, e.key[:], e.nonce[:], uint64(e.nLeaves+1))
		e.chunkOff = 0
		e.leaf.BodyEncrypt(dst[:len(src)], src)
		e.chunkOff += len(src)
	}
}

// encryptComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (e *Encryptor) encryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var tags [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		keccak.EncryptChunksTW128(e.key[:], e.nonce[:], uint64(e.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		e.trunk.AbsorbCVs(tags[:])
		e.nLeaves += 8
		idx += 8
	}

	// Remainder: pad to 8 and use x8 when utilization is high enough.
	if rem := nFlush - idx; rem >= 5 {
		off := idx * ChunkSize
		realBytes := rem * ChunkSize
		var padSrc, padDst [8 * ChunkSize]byte
		copy(padSrc[:realBytes], src[off:off+realBytes])
		keccak.EncryptChunksTW128(e.key[:], e.nonce[:], uint64(e.nLeaves+1), padSrc[:], padDst[:], &tags)
		copy(dst[off:off+realBytes], padDst[:realBytes])
		e.trunk.AbsorbCVs(tags[:rem*leafTagSize])
		e.nLeaves += rem
		idx += rem
	}

	// Small remainder via x1.
	for idx < nFlush {
		off := idx * ChunkSize
		encryptX1(e.key[:], e.nonce[:], uint64(e.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &e.leaf)
		e.trunk.AbsorbCV(&e.leaf)
		e.nLeaves++
		idx++
	}
}

// Finalize returns the authentication tag.
func (e *Encryptor) Finalize() [TagSize]byte {
	return e.finalizeInternal()
}

// Decryptor incrementally decrypts data and computes the authentication tag.
type Decryptor struct {
	cryptor
}

// NewDecryptor returns a new Decryptor initialized with the given key, nonce, and associated data.
func NewDecryptor(key, nonce, ad []byte) (d Decryptor) {
	d.initCryptor(key, nonce, ad)
	return d
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (d *Decryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !d.leafMode {
		// Still on chunk 0: decrypt from trunk.
		n := min(len(src), ChunkSize-d.chunkOff)
		d.trunk.BodyDecrypt(dst[:n], src[:n])
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
		d.leaf.BodyDecrypt(dst[:n], src[:n])
		d.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if d.chunkOff == ChunkSize {
			d.finalizeLeaf()
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
		initLeaf(&d.leaf, d.key[:], d.nonce[:], uint64(d.nLeaves+1))
		d.chunkOff = 0
		d.leaf.BodyDecrypt(dst[:len(src)], src)
		d.chunkOff += len(src)
	}
}

// decryptComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (d *Decryptor) decryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var tags [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		keccak.DecryptChunksTW128(d.key[:], d.nonce[:], uint64(d.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		d.trunk.AbsorbCVs(tags[:])
		d.nLeaves += 8
		idx += 8
	}

	// Remainder: pad to 8 and use x8 when utilization is high enough.
	if rem := nFlush - idx; rem >= 5 {
		off := idx * ChunkSize
		realBytes := rem * ChunkSize
		var padSrc, padDst [8 * ChunkSize]byte
		copy(padSrc[:realBytes], src[off:off+realBytes])
		keccak.DecryptChunksTW128(d.key[:], d.nonce[:], uint64(d.nLeaves+1), padSrc[:], padDst[:], &tags)
		copy(dst[off:off+realBytes], padDst[:realBytes])
		d.trunk.AbsorbCVs(tags[:rem*leafTagSize])
		d.nLeaves += rem
		idx += rem
	}

	// Small remainder via x1.
	for idx < nFlush {
		off := idx * ChunkSize
		decryptX1(d.key[:], d.nonce[:], uint64(d.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &d.leaf)
		d.trunk.AbsorbCV(&d.leaf)
		d.nLeaves++
		idx++
	}
}

// Finalize returns the expected authentication tag.
func (d *Decryptor) Finalize() [TagSize]byte {
	return d.finalizeInternal()
}

func encryptX1(key, nonce []byte, index uint64, pt, ct []byte, d *keccak.State1) {
	initLeaf(d, key, nonce, index)
	done := d.BodyEncryptLoop(pt, ct)
	d.EncryptBytesAt(0, pt[done:], ct[done:])
	d.SetPos(len(pt) - done)
	d.BodyPadStarPermute()
}

func decryptX1(key, nonce []byte, index uint64, ct, pt []byte, d *keccak.State1) {
	initLeaf(d, key, nonce, index)
	done := d.BodyDecryptLoop(ct, pt)
	d.DecryptBytesAt(0, ct[done:], pt[done:])
	d.SetPos(len(ct) - done)
	d.BodyPadStarPermute()
}
