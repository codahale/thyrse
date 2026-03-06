// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"slices"

	"github.com/codahale/thyrse/internal/encoding"
	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192

	leafDS = 0x0B
)

// Hasher is an incremental KT128 instance that implements hash.Hash and io.Reader.
type Hasher struct {
	suffix    []byte        // C || lengthEncode(|C|), precomputed at construction, immutable
	buf       []byte        // buffered message/leaf data
	ts        keccak.Duplex // final-node duplex sponge state
	leafCount int           // total leaf CVs written to ts so far
	ds        byte          // domain separator for finalization (0x07 single-node, 0x06 tree-mode)
	treeMode  bool          // true once S_0 has been flushed to ts
	finalized bool          // true once finalize has completed
	squeezed  bool          // true once PadPermute has been called
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
	suffix = append(suffix, encoding.LengthEncode(uint64(len(c)))...)
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
		h.ts.Reset()
		h.ds = 0x06
		h.ts.Absorb(h.buf[:BlockSize])
		h.ts.Absorb(kt12Marker[:])
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
	var s8 keccak.State8
	var s4 keccak.State4
	var s2 keccak.State2
	var s1 keccak.State1
	idx := 0

	for idx+8 <= nLeaves {
		off := idx * BlockSize
		leafStateX8(data[off:off+8*BlockSize], &s8)
		h.ts.AbsorbCVx8(&s8)
		idx += 8
	}

	for idx+4 <= nLeaves {
		off := idx * BlockSize
		leafStateX4(data[off:off+4*BlockSize], &s4)
		h.ts.AbsorbCVx4(&s4)
		idx += 4
	}

	for idx+2 <= nLeaves {
		off := idx * BlockSize
		leafStateX2(data[off:off+2*BlockSize], &s2)
		h.ts.AbsorbCVx2(&s2)
		idx += 2
	}

	for idx < nLeaves {
		off := idx * BlockSize
		leafStateX1(data[off:off+BlockSize], &s1)
		h.ts.AbsorbCV(&s1)
		idx++
	}

	h.leafCount += nLeaves
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption.
func (h *Hasher) Read(p []byte) (int, error) {
	h.finalize()
	if !h.squeezed {
		h.ts.PadPermute(h.ds)
		h.squeezed = true
	}
	h.ts.Squeeze(p)
	return len(p), nil
}

// Sum appends the current 32-byte hash to b without changing the underlying state.
func (h *Hasher) Sum(b []byte) []byte {
	clone := &Hasher{
		suffix:    h.suffix,
		buf:       slices.Clone(h.buf),
		ts:        h.ts,
		leafCount: h.leafCount,
		ds:        h.ds,
		treeMode:  h.treeMode,
		finalized: h.finalized,
		squeezed:  h.squeezed,
	}
	clone.finalize()

	out := make([]byte, 32)
	_, _ = clone.Read(out)
	return append(b, out...)
}

// Clone returns an independent copy of the Hasher. The original and clone evolve independently.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		suffix:    h.suffix, // immutable, safe to share
		buf:       slices.Clone(h.buf),
		ts:        h.ts,
		leafCount: h.leafCount,
		ds:        h.ds,
		treeMode:  h.treeMode,
		finalized: h.finalized,
		squeezed:  h.squeezed,
	}
}

// Reset resets the Hasher to its initial state, retaining the customization string.
func (h *Hasher) Reset() {
	h.buf = h.buf[:0]
	h.ts.Reset()
	h.ds = 0
	h.leafCount = 0
	h.treeMode = false
	h.finalized = false
	h.squeezed = false
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
			h.ts.Reset()
			h.ds = 0x07
			h.ts.Absorb(h.buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.ts.Reset()
		h.ds = 0x06
		h.ts.Absorb(h.buf[:BlockSize])
		h.ts.Absorb(kt12Marker[:])
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
			var s1 keccak.State1
			off := fullLeaves * BlockSize
			leafStateX1(h.buf[off:], &s1)
			h.ts.AbsorbCV(&s1)
			h.leafCount++
		}
	}

	// Terminator: lengthEncode(leafCount) || 0xFF || 0xFF.
	h.ts.Absorb(encoding.LengthEncode(uint64(h.leafCount)))
	h.ts.Absorb([]byte{0xFF, 0xFF})
}

// kt12Marker is the 8-byte KangarooTwelve marker written after S_0.
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// leafStateX1 computes a single leaf state for TurboSHAKE128(data, 0x0B, 32).
func leafStateX1(data []byte, s *keccak.State1) {
	s.Reset()
	off := s.FastLoopAbsorb168(data)
	s.AbsorbFinal(data[off:], leafDS)
	s.Permute12()
}

// leafStateX2 computes 2 leaf states in parallel.
func leafStateX2(data []byte, s *keccak.State2) {
	s.Reset()
	off := s.FastLoopAbsorb168(data, BlockSize)
	s.AbsorbFinal(data[off:BlockSize], data[BlockSize+off:2*BlockSize], leafDS)
	s.Permute12()
}

// leafStateX4 computes 4 leaf states in parallel.
func leafStateX4(data []byte, s *keccak.State4) {
	s.Reset()
	off := s.FastLoopAbsorb168(data, BlockSize)
	s.AbsorbFinal(
		data[off:BlockSize],
		data[BlockSize+off:2*BlockSize],
		data[2*BlockSize+off:3*BlockSize],
		data[3*BlockSize+off:4*BlockSize],
		leafDS,
	)
	s.Permute12()
}

// leafStateX8 computes 8 leaf states in parallel.
func leafStateX8(data []byte, s *keccak.State8) {
	s.Reset()
	off := s.FastLoopAbsorb168(data, BlockSize)
	s.AbsorbFinal(
		data[off:BlockSize],
		data[BlockSize+off:2*BlockSize],
		data[2*BlockSize+off:3*BlockSize],
		data[3*BlockSize+off:4*BlockSize],
		data[4*BlockSize+off:5*BlockSize],
		data[5*BlockSize+off:6*BlockSize],
		data[6*BlockSize+off:7*BlockSize],
		data[7*BlockSize+off:8*BlockSize],
		leafDS,
	)
	s.Permute12()
}
