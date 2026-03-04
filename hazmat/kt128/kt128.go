// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"slices"

	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192
	// rate128 is the TurboSHAKE128 rate in bytes.
	rate128 = 168

	cvSize = 32 // Chain value size.
	leafDS = 0x0B
)

// Hasher is an incremental KT128 instance that implements hash.Hash and io.Reader.
type Hasher struct {
	suffix      []byte        // C || lengthEncode(|C|), precomputed at construction, immutable
	buf         []byte        // buffered message/leaf data
	tsState     keccak.State1 // final-node sponge state
	tsBuf       [rate128]byte
	tsPos       int
	tsDS        byte
	tsSqueezing bool
	leafCount   int  // total leaf CVs written to ts so far
	treeMode    bool // true once S_0 has been flushed to ts
	finalized   bool // true once finalize has completed
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
		h.tsReset(0x06)
		h.tsWrite(h.buf[:BlockSize])
		h.tsWrite(kt12Marker[:])
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
		h.tsWrite(cvBuf[:8*cvSize])
		idx += 8
	}

	for idx+4 <= nLeaves {
		off := idx * BlockSize
		leafCVsX4(data[off:off+4*BlockSize], cvBuf[:4*cvSize])
		h.tsWrite(cvBuf[:4*cvSize])
		idx += 4
	}

	for idx+2 <= nLeaves {
		off := idx * BlockSize
		leafCVsX2(data[off:off+2*BlockSize], cvBuf[:2*cvSize])
		h.tsWrite(cvBuf[:2*cvSize])
		idx += 2
	}

	for idx < nLeaves {
		off := idx * BlockSize
		leafCVX1(data[off:off+BlockSize], cvBuf[:cvSize])
		h.tsWrite(cvBuf[:cvSize])
		idx++
	}

	h.leafCount += nLeaves
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption.
func (h *Hasher) Read(p []byte) (int, error) {
	h.finalize()
	return h.tsRead(p)
}

// Sum appends the current 32-byte hash to b without changing the underlying state.
func (h *Hasher) Sum(b []byte) []byte {
	clone := &Hasher{
		suffix:      h.suffix,
		buf:         slices.Clone(h.buf),
		tsState:     h.tsState,
		tsBuf:       h.tsBuf,
		tsPos:       h.tsPos,
		tsDS:        h.tsDS,
		tsSqueezing: h.tsSqueezing,
		leafCount:   h.leafCount,
		treeMode:    h.treeMode,
		finalized:   h.finalized,
	}
	clone.finalize()

	out := make([]byte, 32)
	_, _ = clone.tsRead(out)
	return append(b, out...)
}

// Clone returns an independent copy of the Hasher. The original and clone evolve independently.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		suffix:      h.suffix, // immutable, safe to share
		buf:         slices.Clone(h.buf),
		tsState:     h.tsState,
		tsBuf:       h.tsBuf,
		tsPos:       h.tsPos,
		tsDS:        h.tsDS,
		tsSqueezing: h.tsSqueezing,
		leafCount:   h.leafCount,
		treeMode:    h.treeMode,
		finalized:   h.finalized,
	}
}

// Reset resets the Hasher to its initial state, retaining the customization string.
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.tsReset(0)
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
			h.tsReset(0x07)
			h.tsWrite(h.buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.tsReset(0x06)
		h.tsWrite(h.buf[:BlockSize])
		h.tsWrite(kt12Marker[:])
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
			h.tsWrite(cvBuf[:])
			h.leafCount++
		}
	}

	// Terminator: lengthEncode(leafCount) || 0xFF || 0xFF.
	h.tsWrite(lengthEncode(uint64(h.leafCount)))
	h.tsWrite([]byte{0xFF, 0xFF})
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

func (h *Hasher) tsReset(ds byte) {
	h.tsState.Reset()
	clear(h.tsBuf[:])
	h.tsPos = 0
	h.tsDS = ds
	h.tsSqueezing = false
}

func (h *Hasher) tsWrite(p []byte) {
	if h.tsSqueezing {
		panic("kt128: write after read")
	}

	// Fast path: absorb full stripes directly from caller buffer when aligned.
	if h.tsPos == 0 {
		for len(p) >= rate128 {
			h.tsState.AbsorbStripe(rate128, p[:rate128])
			h.tsState.Permute12()
			p = p[rate128:]
		}
	}

	for len(p) > 0 {
		w := min(rate128-h.tsPos, len(p))
		copy(h.tsBuf[h.tsPos:h.tsPos+w], p[:w])
		h.tsPos += w
		p = p[w:]

		if h.tsPos == rate128 {
			h.tsState.AbsorbStripe(rate128, h.tsBuf[:])
			h.tsState.Permute12()
			clear(h.tsBuf[:])
			h.tsPos = 0
		}
	}
}

func (h *Hasher) tsRead(p []byte) (int, error) {
	if !h.tsSqueezing {
		h.tsBuf[h.tsPos] ^= h.tsDS
		h.tsBuf[rate128-1] ^= 0x80
		h.tsState.AbsorbStripe(rate128, h.tsBuf[:])
		h.tsState.Permute12()
		h.tsState.SqueezeStripe(rate128, h.tsBuf[:])
		h.tsPos = 0
		h.tsSqueezing = true
	}

	n := len(p)
	for len(p) > 0 {
		if h.tsPos == rate128 {
			h.tsState.Permute12()
			h.tsState.SqueezeStripe(rate128, h.tsBuf[:])
			h.tsPos = 0
		}
		r := copy(p, h.tsBuf[h.tsPos:])
		h.tsPos += r
		p = p[r:]
	}
	return n, nil
}

// leafCVX1 computes a single leaf CV using TurboSHAKE128(data, 0x0B, 32).
func leafCVX1(data []byte, cv []byte) {
	const rate = rate128

	var s keccak.State1
	off := 0
	for off+rate <= len(data) {
		s.AbsorbStripe(rate, data[off:off+rate])
		s.Permute12()
		off += rate
	}

	var final [rate]byte
	copy(final[:], data[off:])
	final[len(data)-off] ^= leafDS
	final[rate-1] ^= 0x80
	s.AbsorbStripe(rate, final[:])
	s.Permute12()

	s.SqueezeStripe(cvSize, cv)
}

// leafCVsX2 computes 2 leaf CVs in parallel.
func leafCVsX2(data []byte, cv []byte) {
	const rate = rate128

	var s keccak.State2

	off := 0
	for off+rate <= BlockSize {
		s.AbsorbStripe2(
			rate,
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
	s.AbsorbStripe2(rate, final[:rate], final[rate:])
	s.Permute12()

	s.SqueezeStripe(cvSize, cv)
}

// leafCVsX4 computes 4 leaf CVs in parallel.
func leafCVsX4(data []byte, cv []byte) {
	const rate = rate128

	var s keccak.State4

	off := 0
	for off+rate <= BlockSize {
		s.AbsorbStripe4(
			rate,
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
	s.AbsorbStripe4(
		rate,
		final[:rate],
		final[rate:2*rate],
		final[2*rate:3*rate],
		final[3*rate:],
	)
	s.Permute12()

	s.SqueezeStripe(cvSize, cv)
}

// leafCVsX8 computes 8 leaf CVs in parallel.
func leafCVsX8(data []byte, cv []byte) {
	const rate = rate128

	var s keccak.State8

	off := 0
	for off+rate <= BlockSize {
		s.AbsorbStripe8(
			rate,
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
	s.AbsorbStripe8(
		rate,
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

	s.SqueezeStripe(cvSize, cv)
}
