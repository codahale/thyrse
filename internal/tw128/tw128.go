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
func iv(nonce []byte, j uint64) [rate]byte {
	var buf [rate]byte
	var nu [enc.MaxIntSize + 1]byte
	nuSlice := enc.RightEncode(nu[:0], j)
	off := rate - NonceSize - len(nuSlice)
	copy(buf[off:], nonce)
	copy(buf[off+NonceSize:], nuSlice)
	return buf
}

// initTrunk initializes a trunk duplex with K, iv(U,0), and optional AD absorption.
func initTrunk(s *duplex, key, nonce, ad []byte) {
	ivBuf := iv(nonce, 0)
	s.initKeyed(key, ivBuf[:])
	if len(ad) > 0 {
		s.absorb(ad)
		s.absorb([]byte{trailerAD})
		s.padStarPermute()
	}
}

// initLeaf initializes a leaf duplex with K, iv(U,j).
func initLeaf(s *duplex, key, nonce []byte, j uint64) {
	ivBuf := iv(nonce, j)
	s.initKeyed(key, ivBuf[:])
}

type cryptor struct {
	key       [KeySize]byte
	nonce     [NonceSize]byte
	trunk     duplex // trunk duplex state
	leaf      duplex // current leaf duplex state (chunks 1+)
	nLeaves   int    // number of completed leaves
	chunkOff  int    // bytes processed in current chunk
	leafMode  bool   // true after chunk 0 body complete
	finalized bool
	decrypt   bool
}

func (c *cryptor) initCryptor(key, nonce, ad []byte, decrypt bool) {
	copy(c.key[:], key)
	if len(nonce) > 0 {
		copy(c.nonce[:], nonce)
	}
	c.decrypt = decrypt
	initTrunk(&c.trunk, c.key[:], c.nonce[:], ad)
}

// finalizeLeaf squeezes the current leaf's tag and absorbs it into the trunk.
// Uses AbsorbCV to read directly from the leaf's lane-major state, avoiding
// byte serialization.
func (c *cryptor) finalizeLeaf() {
	c.leaf.bodyPadStarPermute()
	c.trunk.absorbCV(&c.leaf)
	c.nLeaves++
	c.chunkOff = 0
}

// transitionToLeafMode finalizes the trunk body phase and enters leaf mode.
func (c *cryptor) transitionToLeafMode() {
	c.trunk.bodyPadStarPermute()
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
		c.trunk.bodyPadStarPermute()
	}

	// Finalize the last leaf if a partial chunk is in progress.
	if c.leafMode && c.chunkOff > 0 {
		c.finalizeLeaf()
	}

	// Tag-absorb phase: leaf tags were absorbed incrementally; finalize with trailer.
	if c.nLeaves > 0 {
		c.trunk.absorb([]byte{trailerTC})
		c.trunk.padStarPermute()
	}

	var tag [TagSize]byte
	c.trunk.squeeze(tag[:])
	return tag
}

func (c *cryptor) xorKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if !c.leafMode {
		// Still on chunk 0.
		n := min(len(src), ChunkSize-c.chunkOff)
		if c.decrypt {
			c.trunk.bodyDecrypt(dst[:n], src[:n])
		} else {
			c.trunk.bodyEncrypt(dst[:n], src[:n])
		}
		c.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if c.chunkOff == ChunkSize && len(src) > 0 {
			c.transitionToLeafMode()
		}

		if len(src) == 0 {
			return
		}
	}

	// Leaf mode: processing chunks 1..n-1.

	// Continue an in-progress partial leaf chunk.
	if c.chunkOff > 0 {
		n := min(len(src), ChunkSize-c.chunkOff)
		if c.decrypt {
			c.leaf.bodyDecrypt(dst[:n], src[:n])
		} else {
			c.leaf.bodyEncrypt(dst[:n], src[:n])
		}
		c.chunkOff += n
		dst = dst[n:]
		src = src[n:]

		if c.chunkOff == ChunkSize {
			c.finalizeLeaf()
		}
	}

	// Process complete leaf chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		c.processComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial leaf chunk with remaining bytes.
	if len(src) > 0 {
		initLeaf(&c.leaf, c.key[:], c.nonce[:], uint64(c.nLeaves+1))
		c.chunkOff = 0
		if c.decrypt {
			c.leaf.bodyDecrypt(dst[:len(src)], src)
		} else {
			c.leaf.bodyEncrypt(dst[:len(src)], src)
		}
		c.chunkOff += len(src)
	}
}

// processComplete processes nFlush complete leaf chunks via x8 SIMD with padding for remainders.
func (c *cryptor) processComplete(dst, src []byte, nFlush int) {
	idx := 0

	var tags [256]byte
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		if c.decrypt {
			decryptChunksTW128(c.key[:], c.nonce[:], uint64(c.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		} else {
			encryptChunksTW128(c.key[:], c.nonce[:], uint64(c.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &tags)
		}
		c.trunk.absorbCVs(tags[:])
		c.nLeaves += 8
		idx += 8
	}

	// Remainder: pad to 8 and use x8 when utilization is high enough.
	if rem := nFlush - idx; rem >= 5 {
		off := idx * ChunkSize
		realBytes := rem * ChunkSize
		var padSrc, padDst [8 * ChunkSize]byte
		copy(padSrc[:realBytes], src[off:off+realBytes])
		if c.decrypt {
			decryptChunksTW128(c.key[:], c.nonce[:], uint64(c.nLeaves+1), padSrc[:], padDst[:], &tags)
		} else {
			encryptChunksTW128(c.key[:], c.nonce[:], uint64(c.nLeaves+1), padSrc[:], padDst[:], &tags)
		}
		copy(dst[off:off+realBytes], padDst[:realBytes])
		c.trunk.absorbCVs(tags[:rem*leafTagSize])
		c.nLeaves += rem
		idx += rem
	}

	// Small remainder via x1.
	for idx < nFlush {
		off := idx * ChunkSize
		if c.decrypt {
			decryptX1(c.key[:], c.nonce[:], uint64(c.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &c.leaf)
		} else {
			encryptX1(c.key[:], c.nonce[:], uint64(c.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &c.leaf)
		}
		c.trunk.absorbCV(&c.leaf)
		c.nLeaves++
		idx++
	}
}

// Encryptor incrementally encrypts data and computes the authentication tag.
type Encryptor struct {
	cryptor
}

// NewEncryptor returns a new Encryptor initialized with the given key, nonce, and associated data.
func NewEncryptor(key, nonce, ad []byte) (e Encryptor) {
	e.initCryptor(key, nonce, ad, false)
	return e
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (e *Encryptor) XORKeyStream(dst, src []byte) { e.xorKeyStream(dst, src) }

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
	d.initCryptor(key, nonce, ad, true)
	return d
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (d *Decryptor) XORKeyStream(dst, src []byte) { d.xorKeyStream(dst, src) }

// Finalize returns the expected authentication tag.
func (d *Decryptor) Finalize() [TagSize]byte {
	return d.finalizeInternal()
}

func encryptX1(key, nonce []byte, index uint64, pt, ct []byte, d *duplex) {
	initLeaf(d, key, nonce, index)
	done := d.bodyEncryptLoop(pt, ct)
	d.encryptBytesAt(0, pt[done:], ct[done:])
	d.setPos(len(pt) - done)
	d.bodyPadStarPermute()
}

func decryptX1(key, nonce []byte, index uint64, ct, pt []byte, d *duplex) {
	initLeaf(d, key, nonce, index)
	done := d.bodyDecryptLoop(ct, pt)
	d.decryptBytesAt(0, ct[done:], pt[done:])
	d.setPos(len(ct) - done)
	d.bodyPadStarPermute()
}
