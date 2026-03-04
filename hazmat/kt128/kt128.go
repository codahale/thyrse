// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"encoding/binary"
	"slices"
	"unsafe"

	"github.com/codahale/thyrse/hazmat/turboshake"
	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192

	cvSize        = 32 // Chain value size.
	leafDS        = 0x0B
	leafRateWords = turboshake.Rate / 8
	cvWords       = cvSize / 8
)

// Hasher is an incremental KT128 instance that implements hash.Hash and io.Reader.
type Hasher struct {
	suffix    []byte            // C || lengthEncode(|C|), precomputed at construction, immutable
	buf       []byte            // buffered message/leaf data
	ts        turboshake.Hasher // final-node hasher
	leafCount int               // total leaf CVs written to ts so far
	treeMode  bool              // true once S_0 has been flushed to ts
	finalized bool              // true once finalize has completed
}

// emptySuffix is the suffix for empty customization: lengthEncode(0) = [0x00].
var emptySuffix = []byte{0x00}

// New returns a new Hasher with empty customization.
func New() *Hasher {
	return &Hasher{suffix: emptySuffix}
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
		h.ts = turboshake.New(0x06)
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		// Keep the one overflow byte.
		h.buf[0] = h.buf[BlockSize]
		h.buf = h.buf[:1]
		h.treeMode = true
	}

	lanes := keccak.AvailableLanes

	// Large-write fast path: process chunks directly from p to avoid copying.
	if len(p) > lanes*BlockSize {
		// Drain any buffered data: flush complete blocks, then complete the
		// partial tail with bytes from p.
		if len(h.buf) > 0 {
			if full := len(h.buf) / BlockSize; full > 0 {
				h.processLeafBatch(h.buf[:full*BlockSize], full)
				remaining := copy(h.buf, h.buf[full*BlockSize:])
				h.buf = h.buf[:remaining]
			}
			if len(h.buf) > 0 {
				need := BlockSize - len(h.buf)
				h.buf = append(h.buf, p[:need]...)
				p = p[need:]
				h.processLeafBatch(h.buf[:BlockSize], 1)
				h.buf = h.buf[:0]
			}
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

// processLeafBatch computes leaf CVs for nLeaves complete chunks using X8→X4→X2→X1 cascade.
func (h *Hasher) processLeafBatch(data []byte, nLeaves int) {
	var cvBuf [8 * cvSize]byte
	idx := 0

	for idx+8 <= nLeaves {
		off := idx * BlockSize
		leafCVsX8(data[off:off+8*BlockSize], cvBuf[:])
		_, _ = h.ts.Write(cvBuf[:8*cvSize])
		idx += 8
	}

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
		ts:        h.ts,
		leafCount: h.leafCount,
		treeMode:  h.treeMode,
		finalized: h.finalized,
	}
	clone.finalize()

	out := make([]byte, 32)
	_, _ = clone.ts.Read(out)
	return append(b, out...)
}

// Clone returns an independent copy of the Hasher. The original and clone evolve independently.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		suffix:    h.suffix, // immutable, safe to share
		buf:       slices.Clone(h.buf),
		ts:        h.ts,
		leafCount: h.leafCount,
		treeMode:  h.treeMode,
		finalized: h.finalized,
	}
}

// Reset resets the Hasher to its initial state, retaining the customization string.
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.ts.Reset(0)
	h.leafCount = 0
	h.treeMode = false
	h.finalized = false
}

// Size returns the default output size in bytes.
func (h *Hasher) Size() int { return 32 }

// BlockSize returns the KT128 chunk size.
func (h *Hasher) BlockSize() int { return BlockSize }

// finalize appends the suffix and computes the final hash.
func (h *Hasher) finalize() {
	if h.finalized {
		return
	}
	h.finalized = true

	// Append suffix to buffered data.
	h.buf = append(h.buf, h.suffix...)

	if !h.treeMode {
		if len(h.buf) <= BlockSize {
			// Single-node: TurboSHAKE128(S, 0x07, L).
			h.ts = turboshake.New(0x07)
			_, _ = h.ts.Write(h.buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.ts = turboshake.New(0x06)
		_, _ = h.ts.Write(h.buf[:BlockSize])
		_, _ = h.ts.Write(kt12Marker[:])
		remaining := copy(h.buf, h.buf[BlockSize:])
		h.buf = h.buf[:remaining]
		h.treeMode = true
	}

	// Process all remaining leaves. The last chunk may be partial.
	nLeaves := (len(h.buf) + BlockSize - 1) / BlockSize
	if nLeaves > 0 {
		fullLeaves := len(h.buf) / BlockSize

		if fullLeaves > 0 {
			h.processLeafBatch(h.buf[:fullLeaves*BlockSize], fullLeaves)
		}

		if nLeaves > fullLeaves {
			var cvBuf [cvSize]byte
			off := fullLeaves * BlockSize
			leafCVX1(h.buf[off:], cvBuf[:])
			_, _ = h.ts.Write(cvBuf[:])
			h.leafCount++
		}
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
	const rate = turboshake.Rate

	var s keccak.State1
	off := 0
	for off+rate <= len(data) {
		absorbRate168State1(&s, data[off:off+rate])
		s.Permute12()
		off += rate
	}

	var final [rate]byte
	copy(final[:], data[off:])
	final[len(data)-off] ^= leafDS
	final[rate-1] ^= 0x80
	absorbRate168State1(&s, final[:])
	s.Permute12()

	extractCVState1(&s, cv)
}

// leafCVsX2 computes 2 leaf CVs in parallel.
func leafCVsX2(data []byte, cv []byte) {
	const rate = turboshake.Rate

	var s keccak.State2

	off := 0
	for off+rate <= BlockSize {
		absorbRate168State2(
			&s,
			data[off:off+rate],
			data[BlockSize+off:BlockSize+off+rate],
		)
		s.Permute12()
		off += rate
	}

	var final [2 * rate]byte
	rem := BlockSize - off
	copy(final[:rem], data[off:off+rem])
	copy(final[rate:rate+rem], data[BlockSize+off:BlockSize+off+rem])
	final[rem] ^= leafDS
	final[rate+rem] ^= leafDS
	final[rate-1] ^= 0x80
	final[2*rate-1] ^= 0x80
	absorbRate168State2(&s, final[:rate], final[rate:])
	s.Permute12()

	extractCVState2(&s, cv)
}

// leafCVsX4 computes 4 leaf CVs in parallel.
func leafCVsX4(data []byte, cv []byte) {
	const rate = turboshake.Rate

	var s keccak.State4

	off := 0
	for off+rate <= BlockSize {
		absorbRate168State4(
			&s,
			data[off:off+rate],
			data[BlockSize+off:BlockSize+off+rate],
			data[2*BlockSize+off:2*BlockSize+off+rate],
			data[3*BlockSize+off:3*BlockSize+off+rate],
		)
		s.Permute12()
		off += rate
	}

	var final [4 * rate]byte
	rem := BlockSize - off
	copy(final[:rem], data[off:off+rem])
	copy(final[rate:rate+rem], data[BlockSize+off:BlockSize+off+rem])
	copy(final[2*rate:2*rate+rem], data[2*BlockSize+off:2*BlockSize+off+rem])
	copy(final[3*rate:3*rate+rem], data[3*BlockSize+off:3*BlockSize+off+rem])
	for inst := range 4 {
		final[inst*rate+rem] ^= leafDS
		final[(inst+1)*rate-1] ^= 0x80
	}
	absorbRate168State4(
		&s,
		final[:rate],
		final[rate:2*rate],
		final[2*rate:3*rate],
		final[3*rate:],
	)
	s.Permute12()

	extractCVState4(&s, cv)
}

// These helpers reinterpret StateN lane-major storage as a flat []uint64.
// This relies on internal/keccak layout stability for Phase 2 hot paths.
func stateWords1(s *keccak.State1) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(s)), keccak.Lanes)
}

func stateWords2(s *keccak.State2) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(s)), keccak.Lanes*2)
}

func stateWords4(s *keccak.State4) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(s)), keccak.Lanes*4)
}

func stateWords8(s *keccak.State8) []uint64 {
	return unsafe.Slice((*uint64)(unsafe.Pointer(s)), keccak.Lanes*8)
}

func absorbRate168State1(s *keccak.State1, in []byte) {
	w := stateWords1(s)
	for lane := range leafRateWords {
		base := lane * 8
		w[lane] ^= binary.LittleEndian.Uint64(in[base : base+8])
	}
}

func absorbRate168State2(s *keccak.State2, in0, in1 []byte) {
	w := stateWords2(s)
	for lane := range leafRateWords {
		base := lane * 8
		slot := lane * 2
		w[slot] ^= binary.LittleEndian.Uint64(in0[base : base+8])
		w[slot+1] ^= binary.LittleEndian.Uint64(in1[base : base+8])
	}
}

func absorbRate168State4(s *keccak.State4, in0, in1, in2, in3 []byte) {
	w := stateWords4(s)
	for lane := range leafRateWords {
		base := lane * 8
		slot := lane * 4
		w[slot] ^= binary.LittleEndian.Uint64(in0[base : base+8])
		w[slot+1] ^= binary.LittleEndian.Uint64(in1[base : base+8])
		w[slot+2] ^= binary.LittleEndian.Uint64(in2[base : base+8])
		w[slot+3] ^= binary.LittleEndian.Uint64(in3[base : base+8])
	}
}

func absorbRate168State8(
	s *keccak.State8,
	in0, in1, in2, in3, in4, in5, in6, in7 []byte,
) {
	w := stateWords8(s)
	for lane := range leafRateWords {
		base := lane * 8
		slot := lane * 8
		w[slot] ^= binary.LittleEndian.Uint64(in0[base : base+8])
		w[slot+1] ^= binary.LittleEndian.Uint64(in1[base : base+8])
		w[slot+2] ^= binary.LittleEndian.Uint64(in2[base : base+8])
		w[slot+3] ^= binary.LittleEndian.Uint64(in3[base : base+8])
		w[slot+4] ^= binary.LittleEndian.Uint64(in4[base : base+8])
		w[slot+5] ^= binary.LittleEndian.Uint64(in5[base : base+8])
		w[slot+6] ^= binary.LittleEndian.Uint64(in6[base : base+8])
		w[slot+7] ^= binary.LittleEndian.Uint64(in7[base : base+8])
	}
}

func extractCVState1(s *keccak.State1, cv []byte) {
	w := stateWords1(s)
	for lane := range cvWords {
		binary.LittleEndian.PutUint64(cv[lane*8:(lane+1)*8], w[lane])
	}
}

func extractCVState2(s *keccak.State2, cv []byte) {
	w := stateWords2(s)
	for inst := range 2 {
		base := inst * cvSize
		for lane := range cvWords {
			binary.LittleEndian.PutUint64(cv[base+lane*8:base+(lane+1)*8], w[lane*2+inst])
		}
	}
}

func extractCVState4(s *keccak.State4, cv []byte) {
	w := stateWords4(s)
	for inst := range 4 {
		base := inst * cvSize
		for lane := range cvWords {
			binary.LittleEndian.PutUint64(cv[base+lane*8:base+(lane+1)*8], w[lane*4+inst])
		}
	}
}

func extractCVState8(s *keccak.State8, cv []byte) {
	w := stateWords8(s)
	for inst := range 8 {
		base := inst * cvSize
		for lane := range cvWords {
			binary.LittleEndian.PutUint64(cv[base+lane*8:base+(lane+1)*8], w[lane*8+inst])
		}
	}
}

// leafCVsX8 computes 8 leaf CVs in parallel.
func leafCVsX8(data []byte, cv []byte) {
	const rate = turboshake.Rate

	var s keccak.State8

	off := 0
	for off+rate <= BlockSize {
		absorbRate168State8(
			&s,
			data[off:off+rate],
			data[BlockSize+off:BlockSize+off+rate],
			data[2*BlockSize+off:2*BlockSize+off+rate],
			data[3*BlockSize+off:3*BlockSize+off+rate],
			data[4*BlockSize+off:4*BlockSize+off+rate],
			data[5*BlockSize+off:5*BlockSize+off+rate],
			data[6*BlockSize+off:6*BlockSize+off+rate],
			data[7*BlockSize+off:7*BlockSize+off+rate],
		)
		s.Permute12()
		off += rate
	}

	var final [8 * rate]byte
	rem := BlockSize - off
	copy(final[:rem], data[off:off+rem])
	copy(final[rate:rate+rem], data[BlockSize+off:BlockSize+off+rem])
	copy(final[2*rate:2*rate+rem], data[2*BlockSize+off:2*BlockSize+off+rem])
	copy(final[3*rate:3*rate+rem], data[3*BlockSize+off:3*BlockSize+off+rem])
	copy(final[4*rate:4*rate+rem], data[4*BlockSize+off:4*BlockSize+off+rem])
	copy(final[5*rate:5*rate+rem], data[5*BlockSize+off:5*BlockSize+off+rem])
	copy(final[6*rate:6*rate+rem], data[6*BlockSize+off:6*BlockSize+off+rem])
	copy(final[7*rate:7*rate+rem], data[7*BlockSize+off:7*BlockSize+off+rem])
	for inst := range 8 {
		final[inst*rate+rem] ^= leafDS
		final[(inst+1)*rate-1] ^= 0x80
	}
	absorbRate168State8(
		&s,
		final[:rate],
		final[rate:2*rate],
		final[2*rate:3*rate],
		final[3*rate:4*rate],
		final[4*rate:5*rate],
		final[5*rate:6*rate],
		final[6*rate:7*rate],
		final[7*rate:],
	)
	s.Permute12()

	extractCVState8(&s, cv)
}
