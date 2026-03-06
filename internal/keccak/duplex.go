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

// AbsorbCV absorbs a 32-byte chain value from s by reading its first 4 lanes.
// The duplex position must be lane-aligned (multiple of 8).
func (d *Duplex) AbsorbCV(s *State1) {
	d.absorbCVWords(s.a[0], s.a[1], s.a[2], s.a[3])
}

// AbsorbCVx2 absorbs 2 chain values (32 bytes each) from s in instance order.
func (d *Duplex) AbsorbCVx2(s *State2) {
	for inst := range 2 {
		d.absorbCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

// AbsorbCVx4 absorbs 4 chain values (32 bytes each) from s in instance order.
func (d *Duplex) AbsorbCVx4(s *State4) {
	for inst := range 4 {
		d.absorbCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

// AbsorbCVx8 absorbs 8 chain values (32 bytes each) from s in instance order.
func (d *Duplex) AbsorbCVx8(s *State8) {
	for inst := range 8 {
		d.absorbCVWords(s.a[0][inst], s.a[1][inst], s.a[2][inst], s.a[3][inst])
	}
}

func (d *Duplex) absorbCVWords(w0, w1, w2, w3 uint64) {
	if d.pos&7 != 0 {
		panic("keccak: AbsorbCV on non-lane-aligned state")
	}
	if d.pos+32 > Rate {
		remaining := (Rate - d.pos) >> 3
		words := [4]uint64{w0, w1, w2, w3}
		for i := range remaining {
			d.s.a[d.pos>>3] ^= words[i]
			d.pos += 8
		}
		d.s.Permute12()
		d.pos = 0
		for i := remaining; i < 4; i++ {
			d.s.a[d.pos>>3] ^= words[i]
			d.pos += 8
		}
		return
	}
	lane := d.pos >> 3
	d.s.a[lane] ^= w0
	d.s.a[lane+1] ^= w1
	d.s.a[lane+2] ^= w2
	d.s.a[lane+3] ^= w3
	d.pos += 32
	if d.pos == Rate {
		d.s.Permute12()
		d.pos = 0
	}
}

// Encrypt XOR-encrypts plaintext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (d *Duplex) Encrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if d.pos > 0 && len(src) > 0 {
		n := min(Rate-d.pos, len(src))
		d.s.EncryptBytesAt(d.pos, src[:n], dst[:n])
		d.pos += n
		src = src[n:]
		dst = dst[n:]
		if d.pos == Rate {
			d.s.Permute12()
			d.pos = 0
		}
	}

	// Encrypt full blocks via FastLoopEncrypt168.
	if d.pos == 0 && len(src) >= Rate {
		done := d.s.FastLoopEncrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Encrypt remaining partial block.
	if len(src) > 0 {
		d.s.EncryptBytesAt(d.pos, src, dst)
		d.pos += len(src)
	}
}

// Decrypt XOR-decrypts ciphertext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (d *Duplex) Decrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if d.pos > 0 && len(src) > 0 {
		n := min(Rate-d.pos, len(src))
		d.s.DecryptBytesAt(d.pos, src[:n], dst[:n])
		d.pos += n
		src = src[n:]
		dst = dst[n:]
		if d.pos == Rate {
			d.s.Permute12()
			d.pos = 0
		}
	}

	// Decrypt full blocks via FastLoopDecrypt168.
	if d.pos == 0 && len(src) >= Rate {
		done := d.s.FastLoopDecrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Decrypt remaining partial block.
	if len(src) > 0 {
		d.s.DecryptBytesAt(d.pos, src, dst)
		d.pos += len(src)
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

// Chain clones a into b, applies pad10*1 padding with dsA on a and dsB on b,
// permutes both in parallel via State2, and leaves both at pos=0 ready to
// squeeze.
func (a *Duplex) Chain(b *Duplex, dsA, dsB byte) {
	*b = *a
	var s2 State2
	for i := range Lanes {
		s2.a[i] = [2]uint64{a.s.a[i], b.s.a[i]}
	}
	xorByteInWord(&s2.a[a.pos>>3][0], a.pos, dsA)
	xorByteInWord(&s2.a[a.pos>>3][1], a.pos, dsB)
	endLane := (Rate - 1) >> 3
	xorByteInWord(&s2.a[endLane][0], Rate-1, 0x80)
	xorByteInWord(&s2.a[endLane][1], Rate-1, 0x80)
	s2.Permute12()
	for i := range Lanes {
		a.s.a[i] = s2.a[i][0]
		b.s.a[i] = s2.a[i][1]
	}
	a.pos = 0
	b.pos = 0
}

// Equal returns 1 if d and other represent identical states, 0 otherwise.
// The comparison is constant-time with respect to the keccak state.
func (d *Duplex) Equal(other *Duplex) int {
	var acc uint64
	for i := range Lanes {
		acc |= d.s.a[i] ^ other.s.a[i]
	}
	acc |= acc >> 32
	acc |= acc >> 16
	acc |= acc >> 8
	acc |= acc >> 4
	acc |= acc >> 2
	acc |= acc >> 1
	lanesEq := int(1 - (acc & 1))

	posAcc := d.pos ^ other.pos
	posAcc |= posAcc >> 16
	posAcc |= posAcc >> 8
	posAcc |= posAcc >> 4
	posAcc |= posAcc >> 2
	posAcc |= posAcc >> 1
	posEq := int(1 - (posAcc & 1))

	return lanesEq & posEq
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
