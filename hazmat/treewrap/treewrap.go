// Package treewrap implements TreeWrap, a tree-parallel authenticated encryption algorithm that uses a Sakura flat-tree
// topology to enable SIMD acceleration on large inputs.
//
// Each leaf operates as an independent SpongeWrap instance using Keccak-p[1600,12], and leaf chain values are
// accumulated into a single authentication tag via TurboSHAKE128. All leaf operations are independent and executed in
// parallel using SIMD-accelerated permutations.
//
// TreeWrap provides both stateful incremental types ([Encryptor] and [Decryptor]) and stateless convenience functions
// ([EncryptAndMAC] and [DecryptAndMAC]). It is intended as a building block for duplex-based protocols, where key
// uniqueness and associated data are managed by the caller. The key MUST be unique per invocation.
package treewrap

import (
	"encoding/binary"

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

// initLeaf initializes a State1 for a leaf sponge (absorb key||index, pad, permute).
func initLeaf(s *keccak.State1, key *[KeySize]byte, index uint64) {
	s.Reset()
	buf := leafPadBuf(key, index)
	s.AbsorbFinal(buf[:], initDS)
	s.Permute12()
}

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each leaf chunk in bytes.
	ChunkSize = 8 * 1024

	initDS         = 0x60                  // Domain separation byte for leaf init (key/index absorption).
	singleNodeDS   = 0x61                  // Domain separation byte for single-node tag.
	intermediateDS = 0x62                  // Domain separation byte for intermediate leaf sponges.
	finalDS        = 0x63                  // Domain separation byte for final leaf sponges.
	tagDS          = 0x64                  // Domain separation byte for tag computation.
	padByte        = intermediateDS ^ 0x80 // Combined padding byte for FastLoop methods.
)

type cryptor struct {
	key        [KeySize]byte
	s          keccak.State1
	h          keccak.TurboSHAKE128
	tagStarted bool
	finalized  bool
	idx        int
	pos        int
	chunkOff   int
}

// finalizeCV squeezes the chain value from the current chunk's sponge state.
func (c *cryptor) finalizeCV() {
	c.s.PadPermute(c.pos, finalDS)
	c.ensureTagStarted()
	c.h.WriteCV(&c.s)
	c.idx++
	c.chunkOff = 0
	c.pos = 0
}

// ensureTagStarted writes the Sakura chaining hop indicator before the first CV.
func (c *cryptor) ensureTagStarted() {
	if !c.tagStarted {
		_, _ = c.h.Write(sakuraTopology[:])
		c.tagStarted = true
	}
}

// finalizeTag writes the Sakura terminator and squeezes the tag.
func (c *cryptor) finalizeTag() (tag [TagSize]byte) {
	_, _ = c.h.Write(lengthEncode(uint64(c.idx)))
	_, _ = c.h.Write([]byte{0xFF, 0xFF})
	_, _ = c.h.Read(tag[:])
	return tag
}

func (c *cryptor) finalizeInternal() [TagSize]byte {
	if c.finalized {
		panic("treewrap: Finalize called more than once")
	}
	c.finalized = true

	if c.chunkOff == 0 && c.idx == 0 {
		// Empty input: process one empty chunk with singleNodeDS fast-path.
		var s0 keccak.State1
		initLeaf(&s0, &c.key, 0)
		s0.PadPermute(0, singleNodeDS)
		var tag [TagSize]byte
		s0.ExtractBytes(tag[:])
		return tag
	}

	if c.idx == 0 {
		// Fast path for n=1: derive tag directly from the single chunk.
		var tag [TagSize]byte
		c.s.PadPermute(c.pos, singleNodeDS)
		c.s.ExtractBytes(tag[:])
		return tag
	}

	if c.chunkOff > 0 {
		c.finalizeCV()
	}

	return c.finalizeTag()
}

// Encryptor incrementally encrypts data and computes the authentication tag. It implements a streaming interface where
// each call to [Encryptor.XORKeyStream] immediately produces ciphertext. Call [Encryptor.Finalize] after all data has
// been processed to obtain the authentication tag.
type Encryptor struct {
	cryptor
}

// NewEncryptor returns a new Encryptor initialized with the given key.
func NewEncryptor(key *[KeySize]byte) Encryptor {
	return Encryptor{
		cryptor: cryptor{
			key: *key,
			h:   keccak.NewTurboSHAKE128(tagDS),
		},
	}
}

// XORKeyStream encrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (e *Encryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if e.idx == 0 && e.chunkOff == ChunkSize && len(src) > 0 {
		e.finalizeCV()
	}

	// Continue an in-progress partial chunk.
	if e.chunkOff > 0 {
		n := min(len(src), ChunkSize-e.chunkOff)
		e.encryptPartial(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]

		if e.chunkOff == ChunkSize {
			if e.idx > 0 || len(src) > 0 {
				e.finalizeCV()
			}
		}
	}

	if e.idx == 0 && e.chunkOff == 0 && len(src) <= ChunkSize {
		initLeaf(&e.s, &e.key, 0)
		e.pos = 0
		e.chunkOff = 0
		e.encryptPartial(dst, src)
		return
	}

	// Process complete chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		e.encryptComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial chunk with remaining bytes.
	if len(src) > 0 {
		initLeaf(&e.s, &e.key, uint64(e.idx))
		e.pos = 0
		e.chunkOff = 0
		e.encryptPartial(dst[:len(src)], src)
	}
}

// encryptPartial processes bytes through the current chunk's sponge state.
func (e *Encryptor) encryptPartial(dst, src []byte) {
	for len(src) > 0 {
		if e.pos == keccak.Rate167 {
			e.s.PadPermute(keccak.Rate167, intermediateDS)
			e.pos = 0
		}

		n := min(keccak.Rate167-e.pos, len(src))
		e.s.EncryptBytesAt(e.pos, src[:n], dst[:n])
		e.pos += n
		e.chunkOff += n
		dst = dst[n:]
		src = src[n:]
	}
}

// encryptComplete processes nFlush complete chunks via the SIMD cascade.
func (e *Encryptor) encryptComplete(dst, src []byte, nFlush int) {
	e.ensureTagStarted()
	idx := 0

	for idx+4 <= nFlush {
		off := idx * ChunkSize
		encryptX4(&e.key, uint64(e.idx), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], &e.h)
		e.idx += 4
		idx += 4
	}

	for idx+2 <= nFlush {
		off := idx * ChunkSize
		encryptX2(&e.key, uint64(e.idx), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], &e.h)
		e.idx += 2
		idx += 2
	}

	for idx < nFlush {
		off := idx * ChunkSize
		encryptX1(&e.key, uint64(e.idx), src[off:off+ChunkSize], dst[off:off+ChunkSize], &e.h)
		e.idx++
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
	return Decryptor{
		cryptor: cryptor{
			key: *key,
			h:   keccak.NewTurboSHAKE128(tagDS),
		},
	}
}

// XORKeyStream decrypts src into dst. Dst and src must overlap entirely or not at all. Len(dst) must be >= len(src).
func (d *Decryptor) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	if d.idx == 0 && d.chunkOff == ChunkSize && len(src) > 0 {
		d.finalizeCV()
	}

	// Continue an in-progress partial chunk.
	if d.chunkOff > 0 {
		n := min(len(src), ChunkSize-d.chunkOff)
		d.decryptPartial(dst[:n], src[:n])
		dst = dst[n:]
		src = src[n:]

		if d.chunkOff == ChunkSize {
			if d.idx > 0 || len(src) > 0 {
				d.finalizeCV()
			}
		}
	}

	if d.idx == 0 && d.chunkOff == 0 && len(src) <= ChunkSize {
		initLeaf(&d.s, &d.key, 0)
		d.pos = 0
		d.chunkOff = 0
		d.decryptPartial(dst, src)
		return
	}

	// Process complete chunks via SIMD cascade.
	if nComplete := len(src) / ChunkSize; nComplete > 0 {
		d.decryptComplete(dst[:nComplete*ChunkSize], src[:nComplete*ChunkSize], nComplete)
		dst = dst[nComplete*ChunkSize:]
		src = src[nComplete*ChunkSize:]
	}

	// Start a new partial chunk with remaining bytes.
	if len(src) > 0 {
		initLeaf(&d.s, &d.key, uint64(d.idx))
		d.pos = 0
		d.chunkOff = 0
		d.decryptPartial(dst[:len(src)], src)
	}
}

// decryptPartial processes bytes through the current chunk's sponge state.
func (d *Decryptor) decryptPartial(dst, src []byte) {
	for len(src) > 0 {
		if d.pos == keccak.Rate167 {
			d.s.PadPermute(keccak.Rate167, intermediateDS)
			d.pos = 0
		}

		n := min(keccak.Rate167-d.pos, len(src))
		d.s.DecryptBytesAt(d.pos, src[:n], dst[:n])
		d.pos += n
		d.chunkOff += n
		dst = dst[n:]
		src = src[n:]
	}
}

// decryptComplete processes nFlush complete chunks via the SIMD cascade.
func (d *Decryptor) decryptComplete(dst, src []byte, nFlush int) {
	d.ensureTagStarted()
	idx := 0

	for idx+4 <= nFlush {
		off := idx * ChunkSize
		decryptX4(&d.key, uint64(d.idx), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], &d.h)
		d.idx += 4
		idx += 4
	}

	for idx+2 <= nFlush {
		off := idx * ChunkSize
		decryptX2(&d.key, uint64(d.idx), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], &d.h)
		d.idx += 2
		idx += 2
	}

	for idx < nFlush {
		off := idx * ChunkSize
		decryptX1(&d.key, uint64(d.idx), src[off:off+ChunkSize], dst[off:off+ChunkSize], &d.h)
		d.idx++
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

// sakuraTopology is The Sakura chaining hop indicator. The byte `0x03` (`0b00000011`) encodes two flags: bit 0
// signals that inner-node chain values follow, and bit 1 signals a single-level tree (chain values feed directly into
// the final node without further tree reduction). The seven zero bytes encode default tree parameters (i.e., no
// subtree interleaving).
var sakuraTopology = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// lengthEncode encodes x as in KangarooTwelve: big-endian with no leading zeros, followed by a byte giving the length
// of the encoding.
func lengthEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x00}
	}

	n := 0
	for v := x; v > 0; v >>= 8 {
		n++
	}

	buf := make([]byte, n+1)
	for i := n - 1; i >= 0; i-- {
		buf[i] = byte(x)
		x >>= 8
	}
	buf[n] = byte(n)

	return buf
}

// finalPos returns the sponge position after encrypting/decrypting chunkLen bytes.
func finalPos(chunkLen int) int {
	if chunkLen == 0 {
		return 0
	}
	p := chunkLen % keccak.Rate167
	if p == 0 {
		return keccak.Rate167
	}
	return p
}

func encryptX1(key *[KeySize]byte, index uint64, pt, ct []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State1
	initBuf := leafPadBuf(key, index)
	s.AbsorbFinal(initBuf[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt167(pt, ct, padByte)
	s.EncryptBytesAt(0, pt[done:], ct[done:])

	s.PadPermute(finalPos(len(pt)), finalDS)
	h.WriteCV(&s)
}

func encryptX2(key *[KeySize]byte, baseIndex uint64, pt, ct []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State2
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	s.AbsorbFinal(b0[:], b1[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt167(pt, ct, ChunkSize, padByte)
	tail := ChunkSize - done
	s.EncryptBytes(0, pt[done:done+tail], ct[done:done+tail])
	s.EncryptBytes(1, pt[ChunkSize+done:ChunkSize+done+tail], ct[ChunkSize+done:ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), finalDS)
	h.WriteCVx2(&s)
}

func encryptX4(key *[KeySize]byte, baseIndex uint64, pt, ct []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State4
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], initDS)
	s.Permute12()

	done := s.FastLoopEncrypt167(pt, ct, ChunkSize, padByte)
	tail := ChunkSize - done
	s.EncryptBytes(0, pt[done:done+tail], ct[done:done+tail])
	s.EncryptBytes(1, pt[ChunkSize+done:ChunkSize+done+tail], ct[ChunkSize+done:ChunkSize+done+tail])
	s.EncryptBytes(2, pt[2*ChunkSize+done:2*ChunkSize+done+tail], ct[2*ChunkSize+done:2*ChunkSize+done+tail])
	s.EncryptBytes(3, pt[3*ChunkSize+done:3*ChunkSize+done+tail], ct[3*ChunkSize+done:3*ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), finalDS)
	h.WriteCVx4(&s)
}

func decryptX1(key *[KeySize]byte, index uint64, ct, pt []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State1
	initBuf := leafPadBuf(key, index)
	s.AbsorbFinal(initBuf[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt167(ct, pt, padByte)
	s.DecryptBytesAt(0, ct[done:], pt[done:])

	s.PadPermute(finalPos(len(ct)), finalDS)
	h.WriteCV(&s)
}

func decryptX2(key *[KeySize]byte, baseIndex uint64, ct, pt []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State2
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	s.AbsorbFinal(b0[:], b1[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt167(ct, pt, ChunkSize, padByte)
	tail := ChunkSize - done
	s.DecryptBytes(0, ct[done:done+tail], pt[done:done+tail])
	s.DecryptBytes(1, ct[ChunkSize+done:ChunkSize+done+tail], pt[ChunkSize+done:ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), finalDS)
	h.WriteCVx2(&s)
}

func decryptX4(key *[KeySize]byte, baseIndex uint64, ct, pt []byte, h *keccak.TurboSHAKE128) {
	var s keccak.State4
	b0, b1 := leafPadBuf(key, baseIndex), leafPadBuf(key, baseIndex+1)
	b2, b3 := leafPadBuf(key, baseIndex+2), leafPadBuf(key, baseIndex+3)
	s.AbsorbFinal(b0[:], b1[:], b2[:], b3[:], initDS)
	s.Permute12()

	done := s.FastLoopDecrypt167(ct, pt, ChunkSize, padByte)
	tail := ChunkSize - done
	s.DecryptBytes(0, ct[done:done+tail], pt[done:done+tail])
	s.DecryptBytes(1, ct[ChunkSize+done:ChunkSize+done+tail], pt[ChunkSize+done:ChunkSize+done+tail])
	s.DecryptBytes(2, ct[2*ChunkSize+done:2*ChunkSize+done+tail], pt[2*ChunkSize+done:2*ChunkSize+done+tail])
	s.DecryptBytes(3, ct[3*ChunkSize+done:3*ChunkSize+done+tail], pt[3*ChunkSize+done:3*ChunkSize+done+tail])

	s.PadPermute(finalPos(ChunkSize), finalDS)
	h.WriteCVx4(&s)
}
