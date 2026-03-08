// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"crypto/subtle"
	"slices"

	"github.com/codahale/thyrse/internal/enc"
	"github.com/codahale/thyrse/internal/keccak"
)

const (
	// BlockSize is the KT128 chunk size in bytes.
	BlockSize = 8192

	leafDS = 0x0B

	// Hasher lifecycle states.
	stateSingle    uint8 = 0 // absorbing, single-node (< 1 chunk seen)
	stateTree      uint8 = 1 // absorbing, tree mode (S_0 flushed)
	stateFinalized uint8 = 2 // finalized and squeezable
)

// Hasher is an incremental KT128 instance.
type Hasher struct {
	buf       []byte        // buffered message/leaf data
	ts        keccak.Duplex // final-node sponge state
	pos       uint64        // total bytes written via Write
	leafCount uint64        // total leaf CVs written to ts so far
	state     uint8         // lifecycle: stateSingle → stateTree → stateFinalized
	ds        byte          // KT128 customization byte for finalization (0x07 single-node, 0x06 tree-mode)
}

// New returns a new Hasher with empty customization.
func New() *Hasher {
	return &Hasher{}
}

// Pos returns the total number of bytes written via Write.
func (h *Hasher) Pos() uint64 {
	return h.pos
}

// Write absorbs message bytes. It must not be called after Read or Sum.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	h.pos += uint64(n)

	if h.state == stateSingle {
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
		h.state = stateTree
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

	h.leafCount += uint64(nLeaves)
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption
// with empty customization.
func (h *Hasher) Read(p []byte) (int, error) {
	h.finalize(nil)
	if h.state != stateFinalized {
		h.ts.PadPermute(h.ds)
		h.state = stateFinalized
	}
	h.ts.Squeeze(p)
	return len(p), nil
}

// ReadCustom squeezes output from the XOF with the given customization string.
// On the first call, it finalizes absorption with the customization suffix.
func (h *Hasher) ReadCustom(custom []byte, p []byte) (int, error) {
	h.finalize(custom)
	if h.state != stateFinalized {
		h.ts.PadPermute(h.ds)
		h.state = stateFinalized
	}
	h.ts.Squeeze(p)
	return len(p), nil
}

// Chain clones the internal state, applies customA and customB as KT128
// customization suffixes to each clone, finalizes both, and squeezes output
// into dstA and dstB respectively. The two outputs are independent.
//
// When both customization strings produce the same suffix length (which is
// always the case for equal-length strings), the final PadPermute is performed
// in parallel using the 2x permutation.
func (h *Hasher) Chain(customA []byte, dstA []byte, customB []byte, dstB []byte) {
	a := h.clone()
	b := h.clone()

	a.finalize(customA)
	b.finalize(customB)

	// When suffixes have equal length, both duplexes end at the same sponge
	// position and we can use parallel PadPermute. Otherwise fall back to
	// sequential.
	if a.ds == b.ds && a.ts.Pos() == b.ts.Pos() {
		a.ts.PadPermute2(&b.ts, a.ds)
	} else {
		a.ts.PadPermute(a.ds)
		b.ts.PadPermute(b.ds)
	}

	a.ts.Squeeze(dstA)
	b.ts.Squeeze(dstB)
}

// clone returns an independent copy of the Hasher.
func (h *Hasher) clone() *Hasher {
	return &Hasher{
		buf:       slices.Clone(h.buf),
		ts:        h.ts,
		pos:       h.pos,
		leafCount: h.leafCount,
		ds:        h.ds,
		state: h.state,
	}
}

// Clone returns an independent copy of the Hasher. The original and clone evolve independently.
func (h *Hasher) Clone() *Hasher {
	return h.clone()
}

// Reset resets the Hasher to its initial state.
func (h *Hasher) Reset() {
	clear(h.buf)
	h.buf = h.buf[:0]
	h.ts.Reset()
	h.pos = 0
	h.ds = 0
	h.leafCount = 0
	h.state = stateSingle
}

// Equal returns 1 if h and other represent identical states, 0 otherwise.
// The comparison is constant-time with respect to buffered data and the
// underlying sponge state.
func (h *Hasher) Equal(other *Hasher) int {
	eq := h.ts.Equal(&other.ts)
	eq &= subtle.ConstantTimeCompare(h.buf, other.buf)
	eq &= subtle.ConstantTimeEq(int32(h.pos>>32), int32(other.pos>>32))
	eq &= subtle.ConstantTimeEq(int32(h.pos), int32(other.pos))
	eq &= subtle.ConstantTimeEq(int32(h.leafCount>>32), int32(other.leafCount>>32))
	eq &= subtle.ConstantTimeEq(int32(h.leafCount), int32(other.leafCount))
	eq &= subtle.ConstantTimeByteEq(h.ds, other.ds)
	eq &= subtle.ConstantTimeByteEq(h.state, other.state)
	return eq
}

// customSuffix appends C || right_encode(|C|) to dst and returns the result.
func customSuffix(dst []byte, c []byte) []byte {
	if len(c) == 0 {
		return append(dst, 0x00)
	}
	dst = append(dst, c...)
	dst = append(dst, enc.LengthEncode(uint64(len(c)))...)
	return dst
}

// finalize appends the customization suffix and computes the final hash.
func (h *Hasher) finalize(custom []byte) {
	if h.state == stateFinalized {
		return
	}

	// Append customization suffix to buffered data.
	h.buf = customSuffix(h.buf, custom)

	if h.state == stateSingle {
		if len(h.buf) <= BlockSize {
			// Single-node: KT128 single-node finalization.
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
		h.state = stateTree
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

	// Terminator: LengthEncode(leafCount) || 0xFF || 0xFF.
	h.ts.Absorb(enc.LengthEncode(h.leafCount))
	h.ts.Absorb([]byte{0xFF, 0xFF})
}

// kt12Marker is the 8-byte KangarooTwelve marker written after S_0.
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// leafStateX1 computes a single KT128 leaf state.
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
