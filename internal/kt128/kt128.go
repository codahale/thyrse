// Package kt128 implements KT128 (KangarooTwelve) as specified in RFC 9861.
//
// KT128 is a tree-hash eXtendable-Output Function (XOF) built on TurboSHAKE128.
// For messages larger than 8192 bytes, it splits input into chunks and computes
// leaf chain values in parallel using SIMD-accelerated Keccak permutations.
package kt128

import (
	"crypto/subtle"
	"hash"
	"slices"

	"github.com/codahale/thyrse/internal/enc"
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
	buf, c    []byte // buffered message/leaf data
	final     sponge // final-node sponge state
	pos       uint64 // total bytes written via Write
	leafCount uint64 // total leaf CVs written to final so far
	state     uint8  // lifecycle: stateSingle -> stateTree -> stateFinalized
	ds        byte   // KT128 customization byte for finalization (0x07 single-node, 0x06 tree-mode)
}

// New returns a new Hasher with the given customization string.
func New(c []byte) *Hasher {
	return &Hasher{c: c}
}

func (h *Hasher) BlockSize() int {
	return BlockSize
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
		h.final.reset()
		h.ds = 0x06
		h.final.absorb(h.buf[:BlockSize])
		h.final.absorb(kt12Marker[:])
		// Keep the one overflow byte.
		h.buf[0] = h.buf[BlockSize]
		h.buf = h.buf[:1]
		h.state = stateTree
	}

	lanes := availableLanes

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

// processLeafBatch computes leaf CVs for nLeaves complete chunks using fused SIMD leaf processing.
func (h *Hasher) processLeafBatch(data []byte, nLeaves int) {
	idx := 0

	var cvs [256]byte
	for idx+8 <= nLeaves {
		off := idx * BlockSize
		processLeaves(data[off:off+8*BlockSize], &cvs)
		h.final.absorbCVs(cvs[:])
		idx += 8
	}

	// Remainder: pad to 8 and use fused path when utilization is high enough.
	if rem := nLeaves - idx; rem >= 5 {
		off := idx * BlockSize
		var padData [8 * BlockSize]byte
		copy(padData[:rem*BlockSize], data[off:off+rem*BlockSize])
		processLeaves(padData[:], &cvs)
		h.final.absorbCVs(cvs[:rem*32])
		idx += rem
	}

	// Small remainder via x1.
	for idx < nLeaves {
		var s1 sponge
		off := idx * BlockSize
		leafStateX1(data[off:off+BlockSize], &s1)
		h.final.absorbCV(&s1)
		idx++
	}

	h.leafCount += uint64(nLeaves)
}

// Read squeezes output from the XOF. On the first call, it finalizes absorption
// with empty customization.
func (h *Hasher) Read(p []byte) (int, error) {
	if h.state != stateFinalized {
		h.buf = customSuffix(h.buf, h.c)
		h.absorbMessage()
		h.final.padPermute(h.ds)
		h.state = stateFinalized
	}
	h.final.squeeze(p)
	return len(p), nil
}

// Chain finalizes the Hasher with two single-byte customization values and
// squeezes independent output into dstA and dstB. The Hasher is consumed and
// must not be used after Chain (call Reset to reuse).
//
// The final pad and permute is performed in parallel using the 2x permutation.
func (h *Hasher) Chain(customA uint8, dstA []byte, customB uint8, dstB []byte) {
	if h.state == stateFinalized {
		return
	}

	// Append the customization suffix for A: [custom, 0x01, 0x01].
	bufLen := len(h.buf)
	h.buf = append(h.buf, customA, 0x01, 0x01)

	// Value-copy the hasher; both copies share h.buf's underlying array.
	a := *h
	b := *h

	// Absorb the message (including suffix A) into a's duplex.
	a.absorbMessage()

	// Overwrite the custom byte in the shared buffer for B.
	h.buf[bufLen] = customB

	// Absorb the message (including suffix B) into b's duplex.
	b.absorbMessage()

	// Both suffixes are the same length, so positions always match.
	a.final.padPermute2(&b.final, a.ds)

	a.final.squeeze(dstA)
	b.final.squeeze(dstB)
}

// Clone returns an independent copy of the Hasher. The original and clone evolve independently.
func (h *Hasher) Clone() *Hasher {
	return &Hasher{
		buf:       slices.Clone(h.buf),
		c:         h.c,
		final:     h.final,
		pos:       h.pos,
		leafCount: h.leafCount,
		ds:        h.ds,
		state:     h.state,
	}
}

// Reset resets the Hasher to its initial state.
func (h *Hasher) Reset() {
	clear(h.buf)
	h.buf = h.buf[:0]
	h.final.reset()
	h.pos = 0
	h.ds = 0
	h.leafCount = 0
	h.state = stateSingle
}

// Equal returns 1 if h and other represent identical states, 0 otherwise.
// The comparison is constant-time with respect to buffered data and the
// underlying sponge state.
func (h *Hasher) Equal(other *Hasher) int {
	eq := h.final.equal(&other.final)
	eq &= subtle.ConstantTimeCompare(h.buf, other.buf)
	eq &= subtle.ConstantTimeEq(int32(h.pos>>32), int32(other.pos>>32))
	eq &= subtle.ConstantTimeEq(int32(h.pos), int32(other.pos))
	eq &= subtle.ConstantTimeEq(int32(h.leafCount>>32), int32(other.leafCount>>32))
	eq &= subtle.ConstantTimeEq(int32(h.leafCount), int32(other.leafCount))
	eq &= subtle.ConstantTimeByteEq(h.ds, other.ds)
	eq &= subtle.ConstantTimeByteEq(h.state, other.state)
	return eq
}

// customSuffix appends C || length_encode(|C|) to dst and returns the result.
func customSuffix(dst []byte, c []byte) []byte {
	dst = append(dst, c...)
	return enc.LengthEncode(dst, uint64(len(c)))
}

// absorbMessage absorbs h.buf into h.final, setting h.ds. It does not modify h.buf.
func (h *Hasher) absorbMessage() {
	buf := h.buf

	if h.state == stateSingle {
		if len(buf) <= BlockSize {
			// Single-node: KT128 single-node finalization.
			h.final.reset()
			h.ds = 0x07
			h.final.absorb(buf)
			return
		}

		// Enter tree mode: flush S_0.
		h.final.reset()
		h.ds = 0x06
		h.final.absorb(buf[:BlockSize])
		h.final.absorb(kt12Marker[:])
		buf = buf[BlockSize:]
	}

	// Process all remaining leaves. The last chunk may be partial.
	fullLeaves := len(buf) / BlockSize
	if fullLeaves > 0 {
		h.processLeafBatch(buf[:fullLeaves*BlockSize], fullLeaves)
	}

	if partial := len(buf) - fullLeaves*BlockSize; partial > 0 {
		var s1 sponge
		leafStateX1(buf[fullLeaves*BlockSize:], &s1)
		h.final.absorbCV(&s1)
		h.leafCount++
	}

	// Terminator: LengthEncode(leafCount) || 0xFF || 0xFF.
	var leBuf [9]byte
	h.final.absorb(enc.LengthEncode(leBuf[:0], h.leafCount))
	h.final.absorb([]byte{0xFF, 0xFF})
}

// kt12Marker is the 8-byte KangarooTwelve marker written after S_0.
var kt12Marker = [8]byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// leafStateX1 computes a single KT128 leaf state.
func leafStateX1(data []byte, s *sponge) {
	s.reset()
	s.absorbAll(data, leafDS)
}

var _ hash.XOF = (*Hasher)(nil)
