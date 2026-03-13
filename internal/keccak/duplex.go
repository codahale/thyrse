package keccak

import (
	"encoding/binary"
)


// Clone returns a copy of the state. State1 is a value type,
// so the struct copy is a deep copy.
func (s *State1) Clone() State1 { return *s }

// Absorb XOR-absorbs data into the sponge state, permuting at rate boundaries.
func (s *State1) Absorb(data []byte) {
	// If we have a partial lane buffered, fill it first.
	if rem := s.pos & 7; rem != 0 {
		need := 8 - rem
		if len(data) < need {
			s.a[s.pos>>3] ^= loadPartialLE(data) << (rem * 8)
			s.pos += len(data)
			return
		}
		// Complete the partial lane.
		var tmp [8]byte
		copy(tmp[rem:], data[:need])
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		s.pos += need
		data = data[need:]
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
	}

	// Absorb full stripes directly via FastLoopAbsorb168.
	if s.pos == 0 && len(data) >= Rate {
		absorbed := s.fastLoopAbsorb168(data)
		data = data[absorbed:]
	}

	// Absorb remaining full lanes.
	for len(data) >= 8 && s.pos+8 <= Rate {
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(data[:8])
		s.pos += 8
		data = data[8:]
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
	}

	// Buffer any remaining partial lane.
	if len(data) > 0 {
		s.a[s.pos>>3] ^= loadPartialLE(data)
		s.pos += len(data)
	}
}

// AbsorbCV absorbs a 32-byte chain value from src by reading its first 4 lanes.
// The position must be lane-aligned (multiple of 8).
func (s *State1) AbsorbCV(src *State1) {
	if s.pos&7 != 0 {
		panic("keccak: AbsorbCV on non-lane-aligned state")
	}
	s.absorbCVlanes(src.a[0], src.a[1], src.a[2], src.a[3])
}

// AbsorbCVx8 absorbs 8 chain values (32 bytes each) from src in instance order.
func (s *State1) AbsorbCVx8(src *State8) {
	if s.pos&7 != 0 {
		panic("keccak: AbsorbCV on non-lane-aligned state")
	}
	for inst := range 8 {
		s.absorbCVlanes(src.a[0][inst], src.a[1][inst], src.a[2][inst], src.a[3][inst])
	}
}

// AbsorbCVx8N absorbs the first n chain values (32 bytes each) from src in instance order.
func (s *State1) AbsorbCVx8N(src *State8, n int) {
	if s.pos&7 != 0 {
		panic("keccak: AbsorbCV on non-lane-aligned state")
	}
	for inst := range n {
		s.absorbCVlanes(src.a[0][inst], src.a[1][inst], src.a[2][inst], src.a[3][inst])
	}
}

// absorbCVlanes absorbs a 4-lane (32-byte) chain value. The caller must ensure
// s.pos is lane-aligned.
func (s *State1) absorbCVlanes(w0, w1, w2, w3 uint64) {
	lane := s.pos >> 3
	remaining := (Rate >> 3) - lane
	if remaining >= 4 {
		s.a[lane] ^= w0
		s.a[lane+1] ^= w1
		s.a[lane+2] ^= w2
		s.a[lane+3] ^= w3
		s.pos += 32
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
		return
	}
	words := [4]uint64{w0, w1, w2, w3}
	for i := range remaining {
		s.a[lane+i] ^= words[i]
	}
	s.Permute12()
	s.pos = 0
	for i := remaining; i < 4; i++ {
		s.a[i-remaining] ^= words[i]
		s.pos += 8
	}
}

// Encrypt XOR-encrypts plaintext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (s *State1) Encrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.encryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
	}

	// Encrypt full blocks via FastLoopEncrypt168.
	if s.pos == 0 && len(src) >= Rate {
		done := s.fastLoopEncrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Encrypt remaining partial block.
	if len(src) > 0 {
		s.encryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// Decrypt XOR-decrypts ciphertext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (s *State1) Decrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.decryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
	}

	// Decrypt full blocks via FastLoopDecrypt168.
	if s.pos == 0 && len(src) >= Rate {
		done := s.fastLoopDecrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Decrypt remaining partial block.
	if len(src) > 0 {
		s.decryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// PadPermute applies pad10*1 padding at the current position with domain
// separation byte ds, then permutes. Resets pos to 0.
func (s *State1) PadPermute(ds byte) {
	s.padPermute(s.pos, ds)
	s.pos = 0
}

// PadPermute2 applies pad10*1 padding with ds to both a and b (which may have
// different states but must be at the same position), permutes both, and
// leaves both at pos=0 ready to squeeze.
func (a *State1) PadPermute2(b *State1, ds byte) {
	if a.pos != b.pos {
		panic("keccak: PadPermute2 with mismatched positions")
	}
	padPermute2(a, b, ds)
	a.pos = 0
	b.pos = 0
}

// Equal returns 1 if s and other represent identical states, 0 otherwise.
// The comparison is constant-time with respect to the keccak state.
func (s *State1) Equal(other *State1) int {
	var acc uint64
	for i := range lanes {
		acc |= s.a[i] ^ other.a[i]
	}
	acc |= acc >> 32
	acc |= acc >> 16
	acc |= acc >> 8
	acc |= acc >> 4
	acc |= acc >> 2
	acc |= acc >> 1
	lanesEq := int(1 - (acc & 1))

	posAcc := s.pos ^ other.pos
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
func (s *State1) Squeeze(dst []byte) {
	for len(dst) > 0 {
		if s.pos == Rate {
			s.Permute12()
			s.pos = 0
		}
		// Squeeze from the current lane.
		lane := s.pos >> 3
		off := s.pos & 7
		if off != 0 {
			// Partial lane: extract remaining bytes from current lane.
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[lane])
			w := copy(dst, tmp[off:])
			s.pos += w
			dst = dst[w:]
			continue
		}
		// Full lanes.
		for len(dst) >= 8 && s.pos+8 <= Rate {
			binary.LittleEndian.PutUint64(dst[:8], s.a[s.pos>>3])
			s.pos += 8
			dst = dst[8:]
		}
		// Partial final lane.
		if len(dst) > 0 && s.pos < Rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[s.pos>>3])
			w := copy(dst, tmp[:])
			s.pos += w
			dst = dst[w:]
		}
	}
}
