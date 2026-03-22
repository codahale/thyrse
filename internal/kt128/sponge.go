package kt128

import "encoding/binary"

type sponge struct {
	a   [lanes]uint64
	pos int
}

func (s *sponge) permute12() {
	if permute12x1Arch(s) {
		return
	}
	keccakP1600x12(&s.a)
}

func (s *sponge) reset() {
	clear(s.a[:])
	s.pos = 0
}

func (s *sponge) fastLoopAbsorb168(in []byte) int {
	n := (len(in) / rate) * rate
	if n > 0 && fastLoopAbsorb168x1Arch(s, in[:n]) {
		return n
	}
	for off := 0; off < n; off += rate {
		p := (*[rate]byte)(in[off : off+rate])
		for lane := range rate >> 3 {
			base := lane << 3
			s.a[lane] ^= binary.LittleEndian.Uint64(p[base : base+8])
		}
		s.permute12()
	}
	return n
}

func (s *sponge) absorbAll(in []byte, ds byte) {
	done := s.fastLoopAbsorb168(in)
	tail := in[done:]
	if len(tail) >= rate {
		panic("kt128: invalid final tail length")
	}
	full := len(tail) >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane] ^= binary.LittleEndian.Uint64(tail[base : base+8])
	}
	if rem := len(tail) & 7; rem != 0 {
		base := full << 3
		s.a[full] ^= loadPartialLE(tail[base : base+rem])
	}
	s.pos = len(tail)
	s.padPermute(ds)
}

func (s *sponge) absorb(data []byte) {
	if rem := s.pos & 7; rem != 0 {
		need := 8 - rem
		if len(data) < need {
			s.a[s.pos>>3] ^= loadPartialLE(data) << (rem * 8)
			s.pos += len(data)
			return
		}
		var tmp [8]byte
		copy(tmp[rem:], data[:need])
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		s.pos += need
		data = data[need:]
		if s.pos == rate {
			s.permute12()
			s.pos = 0
		}
	}

	if s.pos == 0 && len(data) >= rate {
		absorbed := s.fastLoopAbsorb168(data)
		data = data[absorbed:]
	}

	for len(data) >= 8 && s.pos+8 <= rate {
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(data[:8])
		s.pos += 8
		data = data[8:]
		if s.pos == rate {
			s.permute12()
			s.pos = 0
		}
	}

	if len(data) > 0 {
		s.a[s.pos>>3] ^= loadPartialLE(data)
		s.pos += len(data)
	}
}

func (s *sponge) absorbCV(src *sponge) {
	if s.pos&7 != 0 {
		panic("kt128: absorbCV on non-lane-aligned state")
	}
	s.absorbCVlanes(src.a[0], src.a[1], src.a[2], src.a[3])
}

func (s *sponge) absorbCVs(cvs []byte) {
	if s.pos&7 != 0 {
		panic("kt128: absorbCVs on non-lane-aligned state")
	}
	for len(cvs) >= 32 {
		s.absorbCVlanes(
			binary.LittleEndian.Uint64(cvs[0:]),
			binary.LittleEndian.Uint64(cvs[8:]),
			binary.LittleEndian.Uint64(cvs[16:]),
			binary.LittleEndian.Uint64(cvs[24:]),
		)
		cvs = cvs[32:]
	}
}

func (s *sponge) absorbCVlanes(w0, w1, w2, w3 uint64) {
	lane := s.pos >> 3
	remaining := (rate >> 3) - lane
	if remaining >= 4 {
		s.a[lane] ^= w0
		s.a[lane+1] ^= w1
		s.a[lane+2] ^= w2
		s.a[lane+3] ^= w3
		s.pos += 32
		if s.pos == rate {
			s.permute12()
			s.pos = 0
		}
		return
	}

	words := [4]uint64{w0, w1, w2, w3}
	for i := range remaining {
		s.a[lane+i] ^= words[i]
	}
	s.permute12()
	s.pos = 0
	for i := remaining; i < 4; i++ {
		s.a[i-remaining] ^= words[i]
		s.pos += 8
	}
}

func (s *sponge) padPermute(ds byte) {
	xorByteInWord(&s.a[s.pos>>3], s.pos, ds)
	xorByteInWord(&s.a[(rate-1)>>3], rate-1, 0x80)
	s.permute12()
	s.pos = 0
}

func (s *sponge) padPermute2(b *sponge, ds byte) {
	if s.pos != b.pos {
		panic("kt128: padPermute2 with mismatched positions")
	}
	pos := s.pos
	var buf [lanes][2]uint64
	for i := range lanes {
		buf[i][0] = s.a[i]
		buf[i][1] = b.a[i]
	}
	xorByteInWord(&buf[pos>>3][0], pos, ds)
	xorByteInWord(&buf[pos>>3][1], pos, ds)
	endLane := (rate - 1) >> 3
	xorByteInWord(&buf[endLane][0], rate-1, 0x80)
	xorByteInWord(&buf[endLane][1], rate-1, 0x80)
	p1600x2Lane(&buf)
	for i := range lanes {
		s.a[i] = buf[i][0]
		b.a[i] = buf[i][1]
	}
	s.pos = 0
	b.pos = 0
}

func (s *sponge) equal(other *sponge) int {
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
	posEq := 1 - (posAcc & 1)

	return lanesEq & posEq
}

func (s *sponge) squeeze(dst []byte) {
	for len(dst) > 0 {
		if s.pos == rate {
			s.permute12()
			s.pos = 0
		}
		lane := s.pos >> 3
		off := s.pos & 7
		if off != 0 {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[lane])
			n := copy(dst, tmp[off:])
			s.pos += n
			dst = dst[n:]
			continue
		}
		for len(dst) >= 8 && s.pos+8 <= rate {
			binary.LittleEndian.PutUint64(dst[:8], s.a[s.pos>>3])
			s.pos += 8
			dst = dst[8:]
		}
		if len(dst) > 0 && s.pos < rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[s.pos>>3])
			n := copy(dst, tmp[:])
			s.pos += n
			dst = dst[n:]
		}
	}
}
