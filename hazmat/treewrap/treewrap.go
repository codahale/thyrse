// Package treewrap implements TreeWrap, a tree-parallel authenticated encryption algorithm that uses a Sakura flat-tree
// topology with kangaroo hopping to enable SIMD acceleration on large inputs.
//
// The final node (index 0) encrypts chunk 0 directly (the "message hop"). For multi-chunk messages, independent leaves
// (indices 1..n-1) encrypt subsequent chunks and produce chain values that are absorbed into the final node (the
// "chaining hop"). All leaf operations are independent and executed in parallel using SIMD-accelerated permutations.
//
// TreeWrap provides both stateful incremental types ([Encryptor] and [Decryptor]) and stateless convenience functions
// ([EncryptAndMAC] and [DecryptAndMAC]). It is intended as a building block for duplex-based protocols, where key
// uniqueness and associated data are managed by the caller. The key MUST be unique per invocation.
package treewrap

import (
	"encoding/binary"

	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/keccak"
	"github.com/codahale/thyrse/internal/mem"
)

// leafPadBuf builds the leaf init data (key || LE64(index)) for AbsorbFinal.
func leafPadBuf(key *[KeySize]byte, index uint64) [KeySize + 8]byte {
	var buf [KeySize + 8]byte
	copy(buf[:KeySize], key[:])
	binary.LittleEndian.PutUint64(buf[KeySize:], index)
	return buf
}

// initDuplex initializes a duplex (absorb key||index, pad, permute).
func initDuplex(d *keccak.Duplex, key *[KeySize]byte, index uint64) {
	d.Reset()
	buf := leafPadBuf(key, index)
	d.Absorb(buf[:])
	d.PadPermute(initDS)
}

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each leaf chunk in bytes.
	ChunkSize = 8 * 1024

	initDS       = 0x08 // Domain separation byte for duplex init (key/index absorption).
	chainValueDS = 0x0B // Domain separation byte for chain value (Sakura inner node '110').
	tagSingleDS  = 0x07 // Domain separation byte for tag, n=1 (Sakura single-node final '11').
	tagChainDS   = 0x06 // Domain separation byte for tag, n>1 (Sakura chaining-hop final '01').
)

// hopFrame is the Sakura message-hop / chaining-hop framing: '110^{62}' packed LSB-first (8 bytes).
var hopFrame = [8]byte{0x03}

type cryptor struct {
	key       [KeySize]byte
	leaf      keccak.Duplex // current leaf's duplex (for chunks 1+)
	final     keccak.Duplex // final node duplex (encrypts chunk 0, absorbs CVs)
	finalized bool
	nLeaves   int  // number of completed leaf CVs absorbed into final node
	chunkOff  int  // bytes processed in current chunk
	leafMode  bool // true after chunk 0 complete and HOP_FRAME absorbed
}

// finalizeCV squeezes the chain value from the current leaf's duplex and absorbs it into the final node.
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
		panic("treewrap: Finalize called more than once")
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

// NewEncryptor returns a new Encryptor initialized with the given key.
func NewEncryptor(key *[KeySize]byte) Encryptor {
	e := Encryptor{cryptor: cryptor{key: *key}}
	initDuplex(&e.final, key, 0)
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
		initDuplex(&e.leaf, &e.key, uint64(e.nLeaves+1))
		e.chunkOff = 0
		e.leaf.Encrypt(dst[:len(src)], src)
		e.chunkOff += len(src)
	}
}

// encryptComplete processes nFlush complete leaf chunks via the SIMD cascade.
func (e *Encryptor) encryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var s8 keccak.State8
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		encryptX8(&e.key, uint64(e.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &s8)
		e.final.AbsorbCVx8(&s8)
		e.nLeaves += 8
		idx += 8
	}

	var s4 keccak.State4
	for idx+4 <= nFlush {
		off := idx * ChunkSize
		encryptX4(&e.key, uint64(e.nLeaves+1), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], &s4)
		e.final.AbsorbCVx4(&s4)
		e.nLeaves += 4
		idx += 4
	}

	var s2 keccak.State2
	for idx+2 <= nFlush {
		off := idx * ChunkSize
		encryptX2(&e.key, uint64(e.nLeaves+1), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], &s2)
		e.final.AbsorbCVx2(&s2)
		e.nLeaves += 2
		idx += 2
	}

	var s1 keccak.State1
	for idx < nFlush {
		off := idx * ChunkSize
		encryptX1(&e.key, uint64(e.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &s1)
		e.final.AbsorbCV(&s1)
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

// NewDecryptor returns a new Decryptor initialized with the given key.
func NewDecryptor(key *[KeySize]byte) Decryptor {
	d := Decryptor{cryptor: cryptor{key: *key}}
	initDuplex(&d.final, key, 0)
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
		initDuplex(&d.leaf, &d.key, uint64(d.nLeaves+1))
		d.chunkOff = 0
		d.leaf.Decrypt(dst[:len(src)], src)
		d.chunkOff += len(src)
	}
}

// decryptComplete processes nFlush complete leaf chunks via the SIMD cascade.
func (d *Decryptor) decryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	var s8 keccak.State8
	for idx+8 <= nFlush {
		off := idx * ChunkSize
		decryptX8(&d.key, uint64(d.nLeaves+1), src[off:off+8*ChunkSize], dst[off:off+8*ChunkSize], &s8)
		d.final.AbsorbCVx8(&s8)
		d.nLeaves += 8
		idx += 8
	}

	var s4 keccak.State4
	for idx+4 <= nFlush {
		off := idx * ChunkSize
		decryptX4(&d.key, uint64(d.nLeaves+1), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], &s4)
		d.final.AbsorbCVx4(&s4)
		d.nLeaves += 4
		idx += 4
	}

	var s2 keccak.State2
	for idx+2 <= nFlush {
		off := idx * ChunkSize
		decryptX2(&d.key, uint64(d.nLeaves+1), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], &s2)
		d.final.AbsorbCVx2(&s2)
		d.nLeaves += 2
		idx += 2
	}

	var s1 keccak.State1
	for idx < nFlush {
		off := idx * ChunkSize
		decryptX1(&d.key, uint64(d.nLeaves+1), src[off:off+ChunkSize], dst[off:off+ChunkSize], &s1)
		d.final.AbsorbCV(&s1)
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

// EncryptAndMAC encrypts plaintext, appends the ciphertext to dst, and returns the resulting slice along with a
// TagSize-byte authentication tag. The key MUST be unique per invocation.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap plaintext.
func EncryptAndMAC(dst []byte, key *[KeySize]byte, plaintext []byte) ([]byte, [TagSize]byte) {
	ret, ct := mem.SliceForAppend(dst, len(plaintext))
	e := NewEncryptor(key)
	e.XORKeyStream(ct, plaintext)
	return ret, e.Finalize()
}

// DecryptAndMAC decrypts ciphertext, appends the plaintext to dst, and returns the resulting slice along with the
// expected TagSize-byte authentication tag. The caller MUST verify the tag using constant-time comparison before using
// the plaintext.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap ciphertext.
func DecryptAndMAC(dst []byte, key *[KeySize]byte, ciphertext []byte) ([]byte, [TagSize]byte) {
	ret, pt := mem.SliceForAppend(dst, len(ciphertext))
	d := NewDecryptor(key)
	d.XORKeyStream(pt, ciphertext)
	return ret, d.Finalize()
}

// finalPos returns the duplex position after encrypting/decrypting chunkLen bytes.
func finalPos(chunkLen int) int {
	if chunkLen == 0 {
		return 0
	}
	p := chunkLen % keccak.Rate
	if p == 0 {
		return keccak.Rate
	}
	return p
}

func encryptX1(key *[KeySize]byte, index uint64, pt, ct []byte, s *keccak.State1) {
	s.Reset()
	initBuf := leafPadBuf(key, index)
	s.AbsorbFinal(initBuf[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt168(pt, ct)
	s.EncryptBytesAt(0, pt[done:], ct[done:])

	s.PadPermute(finalPos(len(pt)), chainValueDS)
}

func encryptX2(key *[KeySize]byte, baseIndex uint64, pt, ct []byte, s *keccak.State2) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	s.AbsorbFinal(b0[:], b1[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt168(pt, ct, ChunkSize)
	tail := ChunkSize - done
	s.EncryptBytes(0, pt[done:done+tail], ct[done:done+tail])
	s.EncryptBytes(1, pt[ChunkSize+done:ChunkSize+done+tail], ct[ChunkSize+done:ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}

func encryptX4(key *[KeySize]byte, baseIndex uint64, pt, ct []byte, s *keccak.State4) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt168(pt, ct, ChunkSize)
	tail := ChunkSize - done
	s.EncryptBytes(0, pt[done:done+tail], ct[done:done+tail])
	s.EncryptBytes(1, pt[ChunkSize+done:ChunkSize+done+tail], ct[ChunkSize+done:ChunkSize+done+tail])
	s.EncryptBytes(2, pt[2*ChunkSize+done:2*ChunkSize+done+tail], ct[2*ChunkSize+done:2*ChunkSize+done+tail])
	s.EncryptBytes(3, pt[3*ChunkSize+done:3*ChunkSize+done+tail], ct[3*ChunkSize+done:3*ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}

func encryptX8(key *[KeySize]byte, baseIndex uint64, pt, ct []byte, s *keccak.State8) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	b4, b5 := leafPadBuf(key, baseIndex+4), leafPadBuf(key, baseIndex+5)
	b6, b7 := leafPadBuf(key, baseIndex+6), leafPadBuf(key, baseIndex+7)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], b4[:], b5[:], b6[:], b7[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt168(pt, ct, ChunkSize)
	tail := ChunkSize - done
	for inst := range 8 {
		s.EncryptBytes(inst, pt[inst*ChunkSize+done:inst*ChunkSize+done+tail], ct[inst*ChunkSize+done:inst*ChunkSize+done+tail])
	}

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}

func decryptX1(key *[KeySize]byte, index uint64, ct, pt []byte, s *keccak.State1) {
	s.Reset()
	initBuf := leafPadBuf(key, index)
	s.AbsorbFinal(initBuf[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt168(ct, pt)
	s.DecryptBytesAt(0, ct[done:], pt[done:])

	s.PadPermute(finalPos(len(ct)), chainValueDS)
}

func decryptX2(key *[KeySize]byte, baseIndex uint64, ct, pt []byte, s *keccak.State2) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	s.AbsorbFinal(b0[:], b1[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt168(ct, pt, ChunkSize)
	tail := ChunkSize - done
	s.DecryptBytes(0, ct[done:done+tail], pt[done:done+tail])
	s.DecryptBytes(1, ct[ChunkSize+done:ChunkSize+done+tail], pt[ChunkSize+done:ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}

func decryptX4(key *[KeySize]byte, baseIndex uint64, ct, pt []byte, s *keccak.State4) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt168(ct, pt, ChunkSize)
	tail := ChunkSize - done
	s.DecryptBytes(0, ct[done:done+tail], pt[done:done+tail])
	s.DecryptBytes(1, ct[ChunkSize+done:ChunkSize+done+tail], pt[ChunkSize+done:ChunkSize+done+tail])
	s.DecryptBytes(2, ct[2*ChunkSize+done:2*ChunkSize+done+tail], pt[2*ChunkSize+done:2*ChunkSize+done+tail])
	s.DecryptBytes(3, ct[3*ChunkSize+done:3*ChunkSize+done+tail], pt[3*ChunkSize+done:3*ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}

func decryptX8(key *[KeySize]byte, baseIndex uint64, ct, pt []byte, s *keccak.State8) {
	s.Reset()
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	b4, b5 := leafPadBuf(key, baseIndex+4), leafPadBuf(key, baseIndex+5)
	b6, b7 := leafPadBuf(key, baseIndex+6), leafPadBuf(key, baseIndex+7)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], b4[:], b5[:], b6[:], b7[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt168(ct, pt, ChunkSize)
	tail := ChunkSize - done
	for inst := range 8 {
		s.DecryptBytes(inst, ct[inst*ChunkSize+done:inst*ChunkSize+done+tail], pt[inst*ChunkSize+done:inst*ChunkSize+done+tail])
	}

	s.PadPermute(finalPos(ChunkSize), chainValueDS)
}
