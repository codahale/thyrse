// Package turboshake implements TurboSHAKE128 as specified in RFC 9861.
//
// TurboSHAKE128 is an eXtendable-Output Function (XOF) based on the Keccak-p[1600,12] permutation with a rate of 168
// bytes.
package turboshake

import (
	"github.com/codahale/thyrse/hazmat/keccak"
	"github.com/codahale/thyrse/internal/mem"
)

// Rate is the TurboSHAKE128 rate in bytes (200 - 32).
const Rate = 168

// Hasher is an incremental TurboSHAKE128 instance that implements io.ReadWriter.
// Writes absorb data into the sponge and reads squeeze output from it.
// Once Read is called, no further writes are permitted.
type Hasher struct {
	s         [200]byte
	pos       int
	ds        byte
	squeezing bool
}

// New returns a new Hasher with the given domain separation byte.
func New(ds byte) (h Hasher) {
	h.ds = ds
	return h
}

// Reset zeros the hasher and reinitializes it with the given domain separation byte.
func (h *Hasher) Reset(ds byte) {
	clear(h.s[:])
	h.pos = 0
	h.ds = ds
	h.squeezing = false
}

// Write absorbs p into the sponge state. It must not be called after Read.
func (h *Hasher) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		w := min(Rate-h.pos, len(p))
		mem.XORInPlace(h.s[h.pos:h.pos+w], p[:w])
		h.pos += w
		p = p[w:]
		if h.pos == Rate {
			keccak.P1600(&h.s)
			h.pos = 0
		}
	}
	return n, nil
}

// Read squeezes output from the sponge state into p. On the first call,
// it finalizes absorption by applying padding and permuting. Subsequent
// calls continue squeezing.
func (h *Hasher) Read(p []byte) (int, error) {
	if !h.squeezing {
		h.s[h.pos] ^= h.ds
		h.s[Rate-1] ^= 0x80
		keccak.P1600(&h.s)
		h.pos = 0
		h.squeezing = true
	}
	n := len(p)
	for len(p) > 0 {
		if h.pos == Rate {
			keccak.P1600(&h.s)
			h.pos = 0
		}
		r := copy(p, h.s[h.pos:Rate])
		h.pos += r
		p = p[r:]
	}
	return n, nil
}

// Sum computes TurboSHAKE128(msg, ds, outLen) and returns the result.
// The domain separation byte ds must be in the range [0x01, 0x7F].
func Sum(msg []byte, ds byte, outLen int) []byte {
	h := New(ds)
	_, _ = h.Write(msg)
	out := make([]byte, outLen)
	_, _ = h.Read(out)
	return out
}

// Chain clones a into b, updates b with the given domain separation byte, and finalizes both in parallel. After Chain
// returns, both a and b are in squeezing mode and ready for Read.
func Chain(a, b *Hasher, ds byte) {
	if a.squeezing {
		panic("turboshake: parallel finalization with finalized state")
	}

	*b = *a
	a.s[a.pos] ^= a.ds
	a.s[Rate-1] ^= 0x80
	b.s[b.pos] ^= ds
	b.s[Rate-1] ^= 0x80
	keccak.P1600x2(&a.s, &b.s)
	a.pos, b.pos = 0, 0
	a.squeezing, b.squeezing = true, true
}
