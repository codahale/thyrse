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

	"github.com/codahale/thyrse/hazmat/legacykeccak"
	"github.com/codahale/thyrse/hazmat/turboshake"
	"github.com/codahale/thyrse/internal/mem"
)

const (
	// KeySize is the size of the key in bytes.
	KeySize = 32

	// TagSize is the size of the authentication tag in bytes.
	TagSize = 32

	// ChunkSize is the size of each leaf chunk in bytes.
	ChunkSize = 8 * 1024

	cvSize         = 32                  // Chain value size (= capacity).
	blockRate      = turboshake.Rate - 1 // 167: usable data bytes per sponge block.
	initDS         = 0x60                // Domain separation byte for leaf init (key/index absorption).
	singleNodeDS   = 0x61                // Domain separation byte for single-node tag.
	intermediateDS = 0x62                // Domain separation byte for intermediate leaf sponges.
	finalDS        = 0x63                // Domain separation byte for final leaf sponges.
	tagDS          = 0x64                // Domain separation byte for tag computation.
)

type cryptor struct {
	key        [KeySize]byte
	s          [200]byte
	h          turboshake.Hasher
	cvBuf      [4 * cvSize]byte
	tagStarted bool
	finalized  bool
	idx        int
	pos        int
	chunkOff   int
}

// finalizeCV squeezes the chain value from the current chunk's sponge state.
func (c *cryptor) finalizeCV() {
	c.s[c.pos] ^= finalDS
	c.s[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600(&c.s)
	copy(c.cvBuf[:cvSize], c.s[:cvSize])
	c.feedCVs(c.cvBuf[:cvSize])
	c.idx++
	c.chunkOff = 0
	c.pos = 0
}

// feedCVs writes chain values into the hasher with Sakura final-node framing. Before the first CV, it writes the
// Sakura chaining hop indicator.
func (c *cryptor) feedCVs(cvs []byte) {
	if !c.tagStarted {
		_, _ = c.h.Write(sakuraTopology[:])
		c.tagStarted = true
	}
	_, _ = c.h.Write(cvs)
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
		var s0 [200]byte
		leafPad(&s0, &c.key, 0)
		legacykeccak.P1600(&s0)
		s0[0] ^= singleNodeDS
		s0[turboshake.Rate-1] ^= 0x80
		legacykeccak.P1600(&s0)
		var tag [TagSize]byte
		copy(tag[:], s0[:TagSize])
		return tag
	}

	if c.idx == 0 {
		// Fast path for n=1: derive tag directly from the single chunk.
		var tag [TagSize]byte
		c.s[c.pos] ^= singleNodeDS
		c.s[turboshake.Rate-1] ^= 0x80
		legacykeccak.P1600(&c.s)
		copy(tag[:], c.s[:TagSize])
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
			h:   turboshake.New(tagDS),
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
		e.s = [200]byte{}
		leafPad(&e.s, &e.key, 0)
		legacykeccak.P1600(&e.s)
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
		e.s = [200]byte{}
		leafPad(&e.s, &e.key, uint64(e.idx))
		legacykeccak.P1600(&e.s)
		e.pos = 0
		e.chunkOff = 0
		e.encryptPartial(dst[:len(src)], src)
	}
}

// encryptPartial processes bytes through the current chunk's sponge state.
func (e *Encryptor) encryptPartial(dst, src []byte) {
	for len(src) > 0 {
		if e.pos == blockRate {
			e.s[blockRate] ^= intermediateDS
			e.s[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600(&e.s)
			e.pos = 0
		}

		n := min(blockRate-e.pos, len(src))
		mem.XORAndCopy(dst[:n], src[:n], e.s[e.pos:e.pos+n])
		e.pos += n
		e.chunkOff += n
		dst = dst[n:]
		src = src[n:]
	}
}

// encryptComplete processes nFlush complete chunks via the SIMD cascade.
func (e *Encryptor) encryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	for idx+4 <= nFlush {
		off := idx * ChunkSize
		encryptX4(&e.key, uint64(e.idx), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], e.cvBuf[:])
		e.feedCVs(e.cvBuf[:4*cvSize])
		e.idx += 4
		idx += 4
	}

	for idx+2 <= nFlush {
		off := idx * ChunkSize
		encryptX2(&e.key, uint64(e.idx), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], e.cvBuf[:2*cvSize])
		e.feedCVs(e.cvBuf[:2*cvSize])
		e.idx += 2
		idx += 2
	}

	for idx < nFlush {
		off := idx * ChunkSize
		encryptX1(&e.key, uint64(e.idx), src[off:off+ChunkSize], dst[off:off+ChunkSize], e.cvBuf[:cvSize])
		e.feedCVs(e.cvBuf[:cvSize])
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
			h:   turboshake.New(tagDS),
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
		d.s = [200]byte{}
		leafPad(&d.s, &d.key, 0)
		legacykeccak.P1600(&d.s)
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
		d.s = [200]byte{}
		leafPad(&d.s, &d.key, uint64(d.idx))
		legacykeccak.P1600(&d.s)
		d.pos = 0
		d.chunkOff = 0
		d.decryptPartial(dst[:len(src)], src)
	}
}

// decryptPartial processes bytes through the current chunk's sponge state.
func (d *Decryptor) decryptPartial(dst, src []byte) {
	for len(src) > 0 {
		if d.pos == blockRate {
			d.s[blockRate] ^= intermediateDS
			d.s[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600(&d.s)
			d.pos = 0
		}

		n := min(blockRate-d.pos, len(src))
		mem.XORAndReplace(dst[:n], src[:n], d.s[d.pos:d.pos+n])
		d.pos += n
		d.chunkOff += n
		dst = dst[n:]
		src = src[n:]
	}
}

// decryptComplete processes nFlush complete chunks via the SIMD cascade.
func (d *Decryptor) decryptComplete(dst, src []byte, nFlush int) {
	idx := 0

	for idx+4 <= nFlush {
		off := idx * ChunkSize
		decryptX4(&d.key, uint64(d.idx), src[off:off+4*ChunkSize], dst[off:off+4*ChunkSize], d.cvBuf[:])
		d.feedCVs(d.cvBuf[:4*cvSize])
		d.idx += 4
		idx += 4
	}

	for idx+2 <= nFlush {
		off := idx * ChunkSize
		decryptX2(&d.key, uint64(d.idx), src[off:off+2*ChunkSize], dst[off:off+2*ChunkSize], d.cvBuf[:2*cvSize])
		d.feedCVs(d.cvBuf[:2*cvSize])
		d.idx += 2
		idx += 2
	}

	for idx < nFlush {
		off := idx * ChunkSize
		decryptX1(&d.key, uint64(d.idx), src[off:off+ChunkSize], dst[off:off+ChunkSize], d.cvBuf[:cvSize])
		d.feedCVs(d.cvBuf[:cvSize])
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

// leafPad prepares a Keccak state for a leaf sponge init (absorb key || LE64(index)
// and apply padding). The caller must invoke the permutation.
func leafPad(s *[200]byte, key *[KeySize]byte, index uint64) {
	copy(s[:KeySize], key[:])
	binary.LittleEndian.PutUint64(s[KeySize:KeySize+8], index)
	s[KeySize+8] = initDS
	s[turboshake.Rate-1] = 0x80
}

// finalPos returns the sponge position after encrypting/decrypting chunkLen bytes.
func finalPos(chunkLen int) int {
	if chunkLen == 0 {
		return 0
	}
	p := chunkLen % blockRate
	if p == 0 {
		return blockRate
	}
	return p
}

func encryptX1(key *[KeySize]byte, index uint64, pt, ct, cvBuf []byte) {
	var s0 [200]byte
	leafPad(&s0, key, index)
	legacykeccak.P1600(&s0)

	chunkLen := len(pt)
	off := 0
	for off < chunkLen {
		n := min(blockRate, chunkLen-off)
		mem.XORAndCopy(ct[off:off+n], pt[off:off+n], s0[:n])
		off += n
		if off < chunkLen {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600(&s0)
		}
	}

	pos := finalPos(chunkLen)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600(&s0)
	copy(cvBuf[:cvSize], s0[:cvSize])
}

func encryptX2(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	legacykeccak.P1600x2(&s0, &s1)

	pt0, pt1 := pt[:ChunkSize], pt[ChunkSize:2*ChunkSize]
	ct0, ct1 := ct[:ChunkSize], ct[ChunkSize:2*ChunkSize]

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndCopy(ct0[off:off+n], pt0[off:off+n], s0[:n])
		mem.XORAndCopy(ct1[off:off+n], pt1[off:off+n], s1[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			s1[blockRate] ^= intermediateDS
			s1[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= finalDS
	s1[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600x2(&s0, &s1)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:], s1[:cvSize])
}

func encryptX4(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	legacykeccak.P1600x4(&s0, &s1, &s2, &s3)

	pt0, pt1 := pt[:ChunkSize], pt[ChunkSize:2*ChunkSize]
	pt2, pt3 := pt[2*ChunkSize:3*ChunkSize], pt[3*ChunkSize:4*ChunkSize]
	ct0, ct1 := ct[:ChunkSize], ct[ChunkSize:2*ChunkSize]
	ct2, ct3 := ct[2*ChunkSize:3*ChunkSize], ct[3*ChunkSize:4*ChunkSize]

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndCopy(ct0[off:off+n], pt0[off:off+n], s0[:n])
		mem.XORAndCopy(ct1[off:off+n], pt1[off:off+n], s1[:n])
		mem.XORAndCopy(ct2[off:off+n], pt2[off:off+n], s2[:n])
		mem.XORAndCopy(ct3[off:off+n], pt3[off:off+n], s3[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			s1[blockRate] ^= intermediateDS
			s1[turboshake.Rate-1] ^= 0x80
			s2[blockRate] ^= intermediateDS
			s2[turboshake.Rate-1] ^= 0x80
			s3[blockRate] ^= intermediateDS
			s3[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= finalDS
	s1[turboshake.Rate-1] ^= 0x80
	s2[pos] ^= finalDS
	s2[turboshake.Rate-1] ^= 0x80
	s3[pos] ^= finalDS
	s3[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:2*cvSize], s1[:cvSize])
	copy(cvBuf[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cvBuf[3*cvSize:], s3[:cvSize])
}

func decryptX1(key *[KeySize]byte, index uint64, ct, pt, cvBuf []byte) {
	var s0 [200]byte
	leafPad(&s0, key, index)
	legacykeccak.P1600(&s0)

	chunkLen := len(ct)
	off := 0
	for off < chunkLen {
		n := min(blockRate, chunkLen-off)
		mem.XORAndReplace(pt[off:off+n], ct[off:off+n], s0[:n])
		off += n
		if off < chunkLen {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600(&s0)
		}
	}

	pos := finalPos(chunkLen)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600(&s0)
	copy(cvBuf[:cvSize], s0[:cvSize])
}

func decryptX2(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	legacykeccak.P1600x2(&s0, &s1)

	ct0, ct1 := ct[:ChunkSize], ct[ChunkSize:2*ChunkSize]
	pt0, pt1 := pt[:ChunkSize], pt[ChunkSize:2*ChunkSize]

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndReplace(pt0[off:off+n], ct0[off:off+n], s0[:n])
		mem.XORAndReplace(pt1[off:off+n], ct1[off:off+n], s1[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			s1[blockRate] ^= intermediateDS
			s1[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= finalDS
	s1[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600x2(&s0, &s1)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:], s1[:cvSize])
}

func decryptX4(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	legacykeccak.P1600x4(&s0, &s1, &s2, &s3)

	ct0, ct1 := ct[:ChunkSize], ct[ChunkSize:2*ChunkSize]
	ct2, ct3 := ct[2*ChunkSize:3*ChunkSize], ct[3*ChunkSize:4*ChunkSize]
	pt0, pt1 := pt[:ChunkSize], pt[ChunkSize:2*ChunkSize]
	pt2, pt3 := pt[2*ChunkSize:3*ChunkSize], pt[3*ChunkSize:4*ChunkSize]

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndReplace(pt0[off:off+n], ct0[off:off+n], s0[:n])
		mem.XORAndReplace(pt1[off:off+n], ct1[off:off+n], s1[:n])
		mem.XORAndReplace(pt2[off:off+n], ct2[off:off+n], s2[:n])
		mem.XORAndReplace(pt3[off:off+n], ct3[off:off+n], s3[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= intermediateDS
			s0[turboshake.Rate-1] ^= 0x80
			s1[blockRate] ^= intermediateDS
			s1[turboshake.Rate-1] ^= 0x80
			s2[blockRate] ^= intermediateDS
			s2[turboshake.Rate-1] ^= 0x80
			s3[blockRate] ^= intermediateDS
			s3[turboshake.Rate-1] ^= 0x80
			legacykeccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= finalDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= finalDS
	s1[turboshake.Rate-1] ^= 0x80
	s2[pos] ^= finalDS
	s2[turboshake.Rate-1] ^= 0x80
	s3[pos] ^= finalDS
	s3[turboshake.Rate-1] ^= 0x80
	legacykeccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:2*cvSize], s1[:cvSize])
	copy(cvBuf[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cvBuf[3*cvSize:], s3[:cvSize])
}
