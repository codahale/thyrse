package keccak

import "encoding/binary"

// Duplex is a TurboSHAKE128 duplex sponge extended with encrypt and decrypt
// operations. It uses Keccak-p[1600,12] with rate R=168 and pad10*1 padding.
//
// All operations automatically track the byte position within the rate and
// permute at rate boundaries. The caller sequences operations (absorb, encrypt,
// decrypt, pad-permute, squeeze) and passes the domain separation byte to
// PadPermute.
type Duplex struct {
	s   State1
	pos int
}

// Reset zeros the state and resets the position to 0.
func (d *Duplex) Reset() {
	d.s.Reset()
	d.pos = 0
}

// Absorb XOR-absorbs data into the sponge state, permuting at rate boundaries.
func (d *Duplex) Absorb(data []byte) {
	// If we have a partial lane buffered, fill it first.
	if rem := d.pos & 7; rem != 0 {
		need := 8 - rem
		if len(data) < need {
			d.s.a[d.pos>>3] ^= loadPartialLE(data) << (rem * 8)
			d.pos += len(data)
			return
		}
		// Complete the partial lane.
		var tmp [8]byte
		copy(tmp[rem:], data[:need])
		d.s.a[d.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		d.pos += need
		data = data[need:]
		if d.pos == Rate {
			d.s.Permute12()
			d.pos = 0
		}
	}

	// Absorb full stripes directly via FastLoopAbsorb168.
	if d.pos == 0 && len(data) >= Rate {
		absorbed := d.s.FastLoopAbsorb168(data)
		data = data[absorbed:]
	}

	// Absorb remaining full lanes.
	for len(data) >= 8 && d.pos+8 <= Rate {
		d.s.a[d.pos>>3] ^= binary.LittleEndian.Uint64(data[:8])
		d.pos += 8
		data = data[8:]
		if d.pos == Rate {
			d.s.Permute12()
			d.pos = 0
		}
	}

	// Buffer any remaining partial lane.
	if len(data) > 0 {
		d.s.a[d.pos>>3] ^= loadPartialLE(data)
		d.pos += len(data)
	}
}

// PadPermute applies pad10*1 padding at the current position with domain
// separation byte ds, then permutes. Resets pos to 0.
func (d *Duplex) PadPermute(ds byte) {
	xorByteInWord(&d.s.a[d.pos>>3], d.pos, ds)
	xorByteInWord(&d.s.a[(Rate-1)>>3], Rate-1, 0x80)
	d.s.Permute12()
	d.pos = 0
}

// Squeeze extracts bytes from the sponge state into dst, permuting at rate
// boundaries for multi-block output.
func (d *Duplex) Squeeze(dst []byte) {
	for len(dst) > 0 {
		if d.pos == Rate {
			d.s.Permute12()
			d.pos = 0
		}
		// Squeeze from the current lane.
		lane := d.pos >> 3
		off := d.pos & 7
		if off != 0 {
			// Partial lane: extract remaining bytes from current lane.
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], d.s.a[lane])
			w := copy(dst, tmp[off:])
			d.pos += w
			dst = dst[w:]
			continue
		}
		// Full lanes.
		for len(dst) >= 8 && d.pos+8 <= Rate {
			binary.LittleEndian.PutUint64(dst[:8], d.s.a[d.pos>>3])
			d.pos += 8
			dst = dst[8:]
		}
		// Partial final lane.
		if len(dst) > 0 && d.pos < Rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], d.s.a[d.pos>>3])
			w := copy(dst, tmp[:])
			d.pos += w
			dst = dst[w:]
		}
	}
}
