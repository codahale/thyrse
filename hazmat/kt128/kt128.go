// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"slices"

	"github.com/codahale/thyrse/hazmat/keccak"
	"github.com/codahale/thyrse/hazmat/turboshake"
	"github.com/codahale/thyrse/internal/mem"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192

	cvSize = 32 // Chain value size.
	leafDS = 0x0B
)

// Hasher is an incremental KT128 instance that implements hash.Hash and io.Reader.
type Hasher struct {
	suffix    []byte             // C || lengthEncode(|C|), precomputed at construction, immutable
	buf       []byte             // buffered message/leaf data
	ts        *turboshake.Hasher // final-node hasher, nil until tree mode entered or finalized
	leafCount int                // total leaf CVs written to ts so far
	treeMode  bool               // true once S_0 has been flushed to ts
}

// New returns a new Hasher with empty customization.
func New() *Hasher {
	return &Hasher{suffix: lengthEncode(0)}
}

// NewCustom returns a new Hasher with the given customization string.
func NewCustom(c []byte) *Hasher {
	suffix := make([]byte, 0, len(c)+9)
	suffix = append(suffix, c...)
	suffix = append(suffix, lengthEncode(uint64(len(c)))...)
	return &Hasher{suffix: suffix}
}

// Write absorbs message bytes. It must not be called after Read or Sum.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)

	if !h.treeMode {
		// Buffer until we have more than one chunk.
		need := BlockSize + 1 - len(h.buf)
		if need > len(p) {
			// Not enough to enter tree mode; just buffer.
			h.buf = append(h.buf, p...)
			return n, nil
		}

		// Enter tree mode: flush S_0 from buf + start of p.
		h.buf = append(h.buf, p[:need]...)
		p = p[need:]
		h.ts = new(turboshake.New(0x06))
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		// Keep the one overflow byte.
		h.buf[0] = h.buf[BlockSize]
		h.buf = h.buf[:1]
		h.treeMode = true
	}

	lanes := keccak.Lanes

	// Large-write fast path: process chunks directly from p to avoid copying.
	if len(p) > lanes*BlockSize {
		// Complete any partial chunk in buf from p, then process it.
		if len(h.buf) > 0 {
			need := BlockSize - len(h.buf)
			h.buf = append(h.buf, p[:need]...)
			p = p[need:]
			h.processLeafBatch(h.buf[:BlockSize], 1)
			h.buf = h.buf[:0]
		}

		// Process complete chunks directly from p, keeping at least 1 byte back.
		for {
			processable := (len(p) - 1) / BlockSize
			nFlush := (processable / lanes) * lanes
			if nFlush == 0 {
				break
			}
			h.processLeafBatch(p[:nFlush*BlockSize], nFlush)
			p = p[nFlush*BlockSize:]
		}

		// Buffer the tail.
		h.buf = append(h.buf, p...)
		return n, nil
	}

	// Streaming path: accumulate in buf, flush in SIMD-width batches.
	h.buf = append(h.buf, p...)
	for {
		processable := (len(h.buf) - 1) / BlockSize
		nFlush := (processable / lanes) * lanes
		if nFlush == 0 {
			break
		}
		h.processLeafBatch(h.buf[:nFlush*BlockSize], nFlush)
		remaining := copy(h.buf, h.buf[nFlush*BlockSize:])
		h.buf = h.buf[:remaining]
	}
	return n, nil
}

// processLeafBatch computes leaf CVs for nLeaves complete chunks using X4→X2→X1 cascade.
func (h *Hasher) processLeafBatch(data []byte, nLeaves int) {
	var cvBuf [4 * cvSize]byte
	idx := 0

	for idx+4 <= nLeaves {
		off := idx * BlockSize
		leafCVsX4(data[off:off+4*BlockSize], cvBuf[:])
		_, _ = h.ts.Write(cvBuf[:4*cvSize])
		idx += 4
	}

	for idx+2 <= nLeaves {
		off := idx * BlockSize
		leafCVsX2(data[off:off+2*BlockSize], cvBuf[:])
		_, _ = h.ts.Write(cvBuf[:2*cvSize])
		idx += 2
	}

	for idx < nLeaves {
		off := idx * BlockSize
		leafCVX1(data[off:off+BlockSize], cvBuf[:cvSize])
		_, _ = h.ts.Write(cvBuf[:cvSize])
		idx++
	}

	h.leafCount += nLeaves
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption.
func (h *Hasher) Read(p []byte) (int, error) {
	h.finalize()
	return h.ts.Read(p)
}

// Sum appends the current 32-byte hash to b without changing the underlying state.
func (h *Hasher) Sum(b []byte) []byte {
	clone := &Hasher{
		suffix:    h.suffix,
		buf:       slices.Clone(h.buf),
		leafCount: h.leafCount,
		treeMode:  h.treeMode,
	}
	if h.ts != nil {
		clone.ts = new(*h.ts)
	}
	clone.finalize()

	out := make([]byte, 32)
	_, _ = clone.ts.Read(out)
	return append(b, out...)
}

// Reset resets the Hasher to its initial state, retaining the customization string.
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.ts = nil
	h.leafCount = 0
	h.treeMode = false
}

// Size returns the default output size in bytes.
func (h *Hasher) Size() int { return 32 }

// BlockSize returns the KT128 chunk size.
func (h *Hasher) BlockSize() int { return BlockSize }

// finalize appends the suffix and computes the final hash.
func (h *Hasher) finalize() {
	if h.ts != nil && !h.treeMode {
		// Already finalized (single-node path was taken previously via Sum clone).
		return
	}

	// Append suffix to buffered data.
	h.buf = append(h.buf, h.suffix...)

	if !h.treeMode {
		if len(h.buf) <= BlockSize {
			// Single-node: TurboSHAKE128(S, 0x07, L).
			h.ts = new(turboshake.New(0x07))
			_, _ = h.ts.Write(h.buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.ts = new(turboshake.New(0x06))
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		remaining := copy(h.buf, h.buf[BlockSize:])
		h.buf = h.buf[:remaining]
		h.treeMode = true
	}

	// Process all remaining leaves. The last chunk may be partial.
	nLeaves := (len(h.buf) + BlockSize - 1) / BlockSize
	if nLeaves > 0 {
		var cvBuf [4 * cvSize]byte
		idx := 0
		fullLeaves := len(h.buf) / BlockSize

		for idx+4 <= fullLeaves {
			off := idx * BlockSize
			leafCVsX4(h.buf[off:off+4*BlockSize], cvBuf[:])
			_, _ = h.ts.Write(cvBuf[:4*cvSize])
			idx += 4
		}

		for idx+2 <= fullLeaves {
			off := idx * BlockSize
			leafCVsX2(h.buf[off:off+2*BlockSize], cvBuf[:])
			_, _ = h.ts.Write(cvBuf[:2*cvSize])
			idx += 2
		}

		for idx < nLeaves {
			off := idx * BlockSize
			end := min(off+BlockSize, len(h.buf))
			leafCVX1(h.buf[off:end], cvBuf[:cvSize])
			_, _ = h.ts.Write(cvBuf[:cvSize])
			idx++
		}

		h.leafCount += nLeaves
	}

	// Terminator: lengthEncode(leafCount) || 0xFF || 0xFF.
	_, _ = h.ts.Write(lengthEncode(uint64(h.leafCount)))
	_, _ = h.ts.Write([]byte{0xFF, 0xFF})
}

// kt12Marker is the 8-byte KangarooTwelve marker written after S_0.
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

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

// leafCVX1 computes a single leaf CV using TurboSHAKE128(data, 0x0B, 32).
func leafCVX1(data []byte, cv []byte) {
	var s [200]byte
	chunkLen := len(data)
	pos := 0
	off := 0
	for off < chunkLen {
		n := min(turboshake.Rate-pos, chunkLen-off)
		mem.XORInPlace(s[pos:pos+n], data[off:off+n])
		pos += n
		off += n
		if pos == turboshake.Rate {
			keccak.P1600(&s)
			pos = 0
		}
	}
	s[pos] ^= leafDS
	s[turboshake.Rate-1] ^= 0x80
	keccak.P1600(&s)
	copy(cv, s[:cvSize])
}

// leafCVsX2 computes 2 leaf CVs in parallel using P1600x2.
func leafCVsX2(data []byte, cv []byte) {
	var s0, s1 [200]byte
	pos := 0
	off := 0
	for off < BlockSize {
		n := min(turboshake.Rate-pos, BlockSize-off)
		mem.XORInPlace(s0[pos:pos+n], data[off:off+n])
		mem.XORInPlace(s1[pos:pos+n], data[BlockSize+off:BlockSize+off+n])
		pos += n
		off += n
		if pos == turboshake.Rate {
			keccak.P1600x2(&s0, &s1)
			pos = 0
		}
	}
	s0[pos] ^= leafDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[turboshake.Rate-1] ^= 0x80
	keccak.P1600x2(&s0, &s1)
	copy(cv[:cvSize], s0[:cvSize])
	copy(cv[cvSize:], s1[:cvSize])
}

// leafCVsX4 computes 4 leaf CVs in parallel using P1600x4.
func leafCVsX4(data []byte, cv []byte) {
	var s0, s1, s2, s3 [200]byte
	pos := 0
	off := 0
	for off < BlockSize {
		n := min(turboshake.Rate-pos, BlockSize-off)
		mem.XORInPlace(s0[pos:pos+n], data[off:off+n])
		mem.XORInPlace(s1[pos:pos+n], data[BlockSize+off:BlockSize+off+n])
		mem.XORInPlace(s2[pos:pos+n], data[2*BlockSize+off:2*BlockSize+off+n])
		mem.XORInPlace(s3[pos:pos+n], data[3*BlockSize+off:3*BlockSize+off+n])
		pos += n
		off += n
		if pos == turboshake.Rate {
			keccak.P1600x4(&s0, &s1, &s2, &s3)
			pos = 0
		}
	}
	s0[pos] ^= leafDS
	s0[turboshake.Rate-1] ^= 0x80
	s1[pos] ^= leafDS
	s1[turboshake.Rate-1] ^= 0x80
	s2[pos] ^= leafDS
	s2[turboshake.Rate-1] ^= 0x80
	s3[pos] ^= leafDS
	s3[turboshake.Rate-1] ^= 0x80
	keccak.P1600x4(&s0, &s1, &s2, &s3)
	copy(cv[:cvSize], s0[:cvSize])
	copy(cv[cvSize:2*cvSize], s1[:cvSize])
	copy(cv[2*cvSize:3*cvSize], s2[:cvSize])
	copy(cv[3*cvSize:], s3[:cvSize])
}
