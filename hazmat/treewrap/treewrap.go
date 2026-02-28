// Package treewrap implements TreeWrap, a tree-parallel authenticated encryption
// algorithm that uses a KangarooTwelve-like topology to enable SIMD acceleration
// on large inputs.
//
// Each leaf operates as an independent SpongeWrap instance using Keccak-p[1600,12],
// and leaf chain values are accumulated into a single authentication tag via
// TurboSHAKE128. All leaf operations are independent and execute in parallel
// using SIMD-accelerated permutations.
//
// TreeWrap is a pure function with no internal state. It is intended as a building
// block for duplex-based protocols, where key uniqueness and associated data are
// managed by the caller. The key MUST be unique per invocation.
package treewrap

import (
	"encoding/binary"

	"github.com/codahale/thyrse/hazmat/keccak"
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

	rate      = 168      // TurboSHAKE128 rate (200 − 32).
	cvSize    = 32       // Chain value size (= capacity).
	blockRate = rate - 1 // 167: usable data bytes per sponge block.
	leafDS    = 0x60     // Domain separation byte for leaf sponges.
	tagDS     = 0x61     // Domain separation byte for tag computation.
)

// EncryptAndMAC encrypts plaintext, appends the ciphertext to dst, and returns the resulting slice along with a
// TagSize-byte authentication tag. The key MUST be unique per invocation.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0] as dst. Otherwise, the remaining capacity
// of dst must not overlap plaintext.
func EncryptAndMAC(dst []byte, key *[KeySize]byte, plaintext []byte) ([]byte, [TagSize]byte) {
	n := max(1, (len(plaintext)+ChunkSize-1)/ChunkSize)

	ret, ciphertext := mem.SliceForAppend(dst, len(plaintext))
	h := turboshake.New(tagDS)
	var cvBuf [4 * cvSize]byte
	cvCount := 0

	fullChunks := len(plaintext) / ChunkSize
	idx := 0

	for idx+4 <= fullChunks {
		off := idx * ChunkSize
		encryptX4(key, uint64(idx), plaintext[off:off+4*ChunkSize], ciphertext[off:off+4*ChunkSize], cvBuf[:])
		feedCVs(h, cvBuf[:4*cvSize], &cvCount)
		idx += 4
	}

	for idx+2 <= fullChunks {
		off := idx * ChunkSize
		encryptX2(key, uint64(idx), plaintext[off:off+2*ChunkSize], ciphertext[off:off+2*ChunkSize], cvBuf[:2*cvSize])
		feedCVs(h, cvBuf[:2*cvSize], &cvCount)
		idx += 2
	}

	for idx < n {
		off := idx * ChunkSize
		end := min(off+ChunkSize, len(plaintext))
		encryptX1(key, uint64(idx), plaintext[off:end], ciphertext[off:end], cvBuf[:cvSize])
		feedCVs(h, cvBuf[:cvSize], &cvCount)
		idx++
	}

	return ret, finalizeTag(h, n)
}

// DecryptAndMAC decrypts ciphertext, appends the plaintext to dst, and returns the resulting slice along with the
// expected TagSize-byte authentication tag. The caller MUST verify the tag using constant-time comparison before using
// the
// plaintext.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0] as dst. Otherwise, the remaining
// capacity of dst must not overlap ciphertext.
func DecryptAndMAC(dst []byte, key *[KeySize]byte, ciphertext []byte) ([]byte, [TagSize]byte) {
	n := max(1, (len(ciphertext)+ChunkSize-1)/ChunkSize)

	ret, plaintext := mem.SliceForAppend(dst, len(ciphertext))
	h := turboshake.New(tagDS)
	var cvBuf [4 * cvSize]byte
	cvCount := 0

	fullChunks := len(ciphertext) / ChunkSize
	idx := 0

	for idx+4 <= fullChunks {
		off := idx * ChunkSize
		decryptX4(key, uint64(idx), ciphertext[off:off+4*ChunkSize], plaintext[off:off+4*ChunkSize], cvBuf[:])
		feedCVs(h, cvBuf[:4*cvSize], &cvCount)
		idx += 4
	}

	for idx+2 <= fullChunks {
		off := idx * ChunkSize
		decryptX2(key, uint64(idx), ciphertext[off:off+2*ChunkSize], plaintext[off:off+2*ChunkSize], cvBuf[:2*cvSize])
		feedCVs(h, cvBuf[:2*cvSize], &cvCount)
		idx += 2
	}

	for idx < n {
		off := idx * ChunkSize
		end := min(off+ChunkSize, len(ciphertext))
		decryptX1(key, uint64(idx), ciphertext[off:end], plaintext[off:end], cvBuf[:cvSize])
		feedCVs(h, cvBuf[:cvSize], &cvCount)
		idx++
	}

	return ret, finalizeTag(h, n)
}

// kt12Marker is the 8-byte KangarooTwelve marker written after cv[0].
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// feedCVs writes chain values into the hasher with KT12 final-node framing.
// After the first CV, it inserts the KT12 marker. cvCount tracks how many
// CVs have been written so far.
func feedCVs(h *turboshake.Hasher, cvs []byte, cvCount *int) {
	for len(cvs) >= cvSize {
		_, _ = h.Write(cvs[:cvSize])
		cvs = cvs[cvSize:]
		*cvCount++
		if *cvCount == 1 {
			_, _ = h.Write(kt12Marker[:])
		}
	}
}

// finalizeTag writes the KT12 terminator and squeezes the tag.
func finalizeTag(h *turboshake.Hasher, n int) (tag [TagSize]byte) {
	_, _ = h.Write(lengthEncode(uint64(n - 1)))
	_, _ = h.Write([]byte{0xFF, 0xFF})
	_, _ = h.Read(tag[:])
	return tag
}

// lengthEncode encodes x as in KangarooTwelve: big-endian with no leading zeros,
// followed by a byte giving the length of the encoding.
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
	s[KeySize+8] = leafDS
	s[rate-1] = 0x80
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
	keccak.P1600(&s0)

	chunkLen := len(pt)
	off := 0
	for off < chunkLen {
		n := min(blockRate, chunkLen-off)
		mem.XORAndCopy(ct[off:off+n], pt[off:off+n], s0[:n])
		off += n
		if off < chunkLen {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			keccak.P1600(&s0)
		}
	}

	pos := finalPos(chunkLen)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	keccak.P1600(&s0)
	copy(cvBuf[:cvSize], s0[:cvSize])
}

func encryptX2(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndCopy(ct[off:off+n], pt[off:off+n], s0[:n])
		mem.XORAndCopy(ct[ChunkSize+off:ChunkSize+off+n], pt[ChunkSize+off:ChunkSize+off+n], s1[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			s1[blockRate] ^= leafDS
			s1[rate-1] ^= 0x80
			keccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[rate-1] ^= 0x80
	keccak.P1600x2(&s0, &s1)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:], s1[:cvSize])
}

func encryptX4(key *[KeySize]byte, baseIndex uint64, pt, ct, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndCopy(ct[off:off+n], pt[off:off+n], s0[:n])
		mem.XORAndCopy(ct[ChunkSize+off:ChunkSize+off+n], pt[ChunkSize+off:ChunkSize+off+n], s1[:n])
		mem.XORAndCopy(ct[2*ChunkSize+off:2*ChunkSize+off+n], pt[2*ChunkSize+off:2*ChunkSize+off+n], s2[:n])
		mem.XORAndCopy(ct[3*ChunkSize+off:3*ChunkSize+off+n], pt[3*ChunkSize+off:3*ChunkSize+off+n], s3[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			s1[blockRate] ^= leafDS
			s1[rate-1] ^= 0x80
			s2[blockRate] ^= leafDS
			s2[rate-1] ^= 0x80
			s3[blockRate] ^= leafDS
			s3[rate-1] ^= 0x80
			keccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[rate-1] ^= 0x80
	s2[pos] ^= leafDS
	s2[rate-1] ^= 0x80
	s3[pos] ^= leafDS
	s3[rate-1] ^= 0x80
	keccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:2*cvSize], s1[:cvSize])
	copy(cvBuf[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cvBuf[3*cvSize:], s3[:cvSize])
}

func decryptX1(key *[KeySize]byte, index uint64, ct, pt, cvBuf []byte) {
	var s0 [200]byte
	leafPad(&s0, key, index)
	keccak.P1600(&s0)

	chunkLen := len(ct)
	off := 0
	for off < chunkLen {
		n := min(blockRate, chunkLen-off)
		mem.XORAndReplace(pt[off:off+n], ct[off:off+n], s0[:n])
		off += n
		if off < chunkLen {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			keccak.P1600(&s0)
		}
	}

	pos := finalPos(chunkLen)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	keccak.P1600(&s0)
	copy(cvBuf[:cvSize], s0[:cvSize])
}

func decryptX2(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	keccak.P1600x2(&s0, &s1)

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndReplace(pt[off:off+n], ct[off:off+n], s0[:n])
		mem.XORAndReplace(pt[ChunkSize+off:ChunkSize+off+n], ct[ChunkSize+off:ChunkSize+off+n], s1[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			s1[blockRate] ^= leafDS
			s1[rate-1] ^= 0x80
			keccak.P1600x2(&s0, &s1)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[rate-1] ^= 0x80
	keccak.P1600x2(&s0, &s1)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:], s1[:cvSize])
}

func decryptX4(key *[KeySize]byte, baseIndex uint64, ct, pt, cvBuf []byte) {
	var s0, s1, s2, s3 [200]byte
	leafPad(&s0, key, baseIndex)
	leafPad(&s1, key, baseIndex+1)
	leafPad(&s2, key, baseIndex+2)
	leafPad(&s3, key, baseIndex+3)
	keccak.P1600x4(&s0, &s1, &s2, &s3)

	off := 0
	for off < ChunkSize {
		n := min(blockRate, ChunkSize-off)
		mem.XORAndReplace(pt[off:off+n], ct[off:off+n], s0[:n])
		mem.XORAndReplace(pt[ChunkSize+off:ChunkSize+off+n], ct[ChunkSize+off:ChunkSize+off+n], s1[:n])
		mem.XORAndReplace(pt[2*ChunkSize+off:2*ChunkSize+off+n], ct[2*ChunkSize+off:2*ChunkSize+off+n], s2[:n])
		mem.XORAndReplace(pt[3*ChunkSize+off:3*ChunkSize+off+n], ct[3*ChunkSize+off:3*ChunkSize+off+n], s3[:n])
		off += n
		if off < ChunkSize {
			s0[blockRate] ^= leafDS
			s0[rate-1] ^= 0x80
			s1[blockRate] ^= leafDS
			s1[rate-1] ^= 0x80
			s2[blockRate] ^= leafDS
			s2[rate-1] ^= 0x80
			s3[blockRate] ^= leafDS
			s3[rate-1] ^= 0x80
			keccak.P1600x4(&s0, &s1, &s2, &s3)
		}
	}

	pos := finalPos(ChunkSize)
	s0[pos] ^= leafDS
	s0[rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[rate-1] ^= 0x80
	s2[pos] ^= leafDS
	s2[rate-1] ^= 0x80
	s3[pos] ^= leafDS
	s3[rate-1] ^= 0x80
	keccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cvBuf[:cvSize], s0[:cvSize])
	copy(cvBuf[cvSize:2*cvSize], s1[:cvSize])
	copy(cvBuf[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cvBuf[3*cvSize:], s3[:cvSize])
}
