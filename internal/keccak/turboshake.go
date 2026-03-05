package keccak

import "encoding/binary"

// TurboSHAKE128 is a TurboSHAKE128 instance built on State1.
//
// It implements a sponge with rate 168, absorbing via Write and squeezing via
// Read. WriteCV methods absorb chain values directly from keccak state words,
// avoiding intermediate byte encoding.
type TurboSHAKE128 struct {
	s         State1
	pos       int
	ds        byte
	squeezing bool
}

// NewTurboSHAKE128 returns a TurboSHAKE128 initialized with the given domain separation byte.
func NewTurboSHAKE128(ds byte) TurboSHAKE128 {
	return TurboSHAKE128{ds: ds}
}

// Reset zeros the state and reinitializes it with the given domain separation byte.
func (t *TurboSHAKE128) Reset(ds byte) {
	t.s.Reset()
	t.pos = 0
	t.ds = ds
	t.squeezing = false
}

// Write absorbs p into the sponge state. It must not be called after Read.
func (t *TurboSHAKE128) Write(p []byte) (int, error) {
	n := len(p)

	// If we have a partial lane buffered, fill it first.
	if rem := t.pos & 7; rem != 0 {
		need := 8 - rem
		if len(p) < need {
			t.s.a[t.pos>>3] ^= loadPartialLE(p) << (rem * 8)
			t.pos += len(p)
			return n, nil
		}
		// Complete the partial lane.
		var tmp [8]byte
		copy(tmp[rem:], p[:need])
		t.s.a[t.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		t.pos += need
		p = p[need:]
		if t.pos == Rate {
			t.s.Permute12()
			t.pos = 0
		}
	}

	// Absorb full stripes directly via FastLoopAbsorb168.
	if t.pos == 0 && len(p) >= Rate {
		absorbed := t.s.FastLoopAbsorb168(p)
		p = p[absorbed:]
	}

	// Absorb remaining full lanes.
	for len(p) >= 8 && t.pos+8 <= Rate {
		t.s.a[t.pos>>3] ^= binary.LittleEndian.Uint64(p[:8])
		t.pos += 8
		p = p[8:]
		if t.pos == Rate {
			t.s.Permute12()
			t.pos = 0
		}
	}

	// Buffer any remaining partial lane.
	if len(p) > 0 {
		t.s.a[t.pos>>3] ^= loadPartialLE(p)
		t.pos += len(p)
	}

	return n, nil
}

// WriteCV absorbs a 32-byte chain value from s by reading its first 4 lanes.
func (t *TurboSHAKE128) WriteCV(s *State1) {
	t.writeCVWords(s.a[0], s.a[1], s.a[2], s.a[3])
}

// WriteCVx2 absorbs 2 chain values (32 bytes each) from s in instance order.
func (t *TurboSHAKE128) WriteCVx2(s *State2) {
	for inst := range 2 {
		t.writeCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

// WriteCVx4 absorbs 4 chain values (32 bytes each) from s in instance order.
func (t *TurboSHAKE128) WriteCVx4(s *State4) {
	for inst := range 4 {
		t.writeCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

// WriteCVx8 absorbs 8 chain values (32 bytes each) from s in instance order.
func (t *TurboSHAKE128) WriteCVx8(s *State8) {
	for inst := range 8 {
		t.writeCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

// writeCVWords absorbs 4 uint64 words (32 bytes) into the sponge.
// CV absorption always starts lane-aligned and 32 < 168, so a CV never
// straddles a permutation boundary.
func (t *TurboSHAKE128) writeCVWords(w0, w1, w2, w3 uint64) {
	if t.pos&7 != 0 {
		panic("keccak: WriteCV on non-lane-aligned state")
	}

	// 32 bytes = 4 lanes. Rate is 168 = 21 lanes, so at most we need to
	// permute once if pos > (Rate - 32).
	if t.pos+32 > Rate {
		// Fill remaining lanes in this block, permute, then continue.
		remaining := (Rate - t.pos) >> 3
		words := [4]uint64{w0, w1, w2, w3}
		for i := range remaining {
			t.s.a[t.pos>>3] ^= words[i]
			t.pos += 8
		}
		t.s.Permute12()
		t.pos = 0
		for i := remaining; i < 4; i++ {
			t.s.a[t.pos>>3] ^= words[i]
			t.pos += 8
		}
		return
	}

	lane := t.pos >> 3
	t.s.a[lane] ^= w0
	t.s.a[lane+1] ^= w1
	t.s.a[lane+2] ^= w2
	t.s.a[lane+3] ^= w3
	t.pos += 32
	if t.pos == Rate {
		t.s.Permute12()
		t.pos = 0
	}
}

// Read squeezes output from the sponge state into p. On the first call,
// it finalizes absorption by applying padding and permuting.
func (t *TurboSHAKE128) Read(p []byte) (int, error) {
	if !t.squeezing {
		// Apply domain separation and padding, then permute.
		xorByteInWord(&t.s.a[t.pos>>3], t.pos, t.ds)
		xorByteInWord(&t.s.a[(Rate-1)>>3], Rate-1, 0x80)
		t.s.Permute12()
		t.pos = 0
		t.squeezing = true
	}

	n := len(p)
	for len(p) > 0 {
		if t.pos == Rate {
			t.s.Permute12()
			t.pos = 0
		}
		// Squeeze from the current lane.
		lane := t.pos >> 3
		off := t.pos & 7
		if off != 0 {
			// Partial lane: extract remaining bytes from current lane.
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], t.s.a[lane])
			w := copy(p, tmp[off:])
			t.pos += w
			p = p[w:]
			continue
		}
		// Full lanes.
		for len(p) >= 8 && t.pos+8 <= Rate {
			binary.LittleEndian.PutUint64(p[:8], t.s.a[t.pos>>3])
			t.pos += 8
			p = p[8:]
		}
		// Partial final lane.
		if len(p) > 0 && t.pos < Rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], t.s.a[t.pos>>3])
			w := copy(p, tmp[:])
			t.pos += w
			p = p[w:]
		}
	}
	return n, nil
}
