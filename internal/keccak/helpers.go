package keccak

import "encoding/binary"

const rate168 = 168

func validateStripe(width, n int) {
	if n != width*rate168 {
		panic("keccak: invalid stripe length")
	}
}

func loadPartialLE(in []byte) uint64 {
	var v uint64
	for i := range in {
		v |= uint64(in[i]) << (8 * i)
	}
	return v
}

func xorByteInWord(w *uint64, pos int, b byte) {
	shift := uint((pos & 7) << 3)
	*w ^= uint64(b) << shift
}

func (s *State1) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State1) FastLoopAbsorb168(in []byte) int {
	n := (len(in) / rate168) * rate168
	for off := 0; off < n; off += rate168 {
		var in2 []byte = in[off : off+rate168]
		if len(in2) != rate168 {
			panic("keccak: invalid stripe length")
		}
		validateStripe(1, len(in2))
		full := rate168 >> 3
		for lane := range full {
			base := lane << 3
			s.a[lane] ^= binary.LittleEndian.Uint64(in2[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs a final partial 168-byte block and applies Keccak padding.
func (s *State1) AbsorbFinal(tail []byte, ds byte) {

	if len(tail) >= rate168 {
		panic("keccak: invalid final tail length")
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
	xorByteInWord(&s.a[len(tail)>>3], len(tail), ds)
	xorByteInWord(&s.a[(rate168-1)>>3], rate168-1, 0x80)
}

func (s *State2) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State2) FastLoopAbsorb168(in0, in1 []byte) int {
	n := min(len(in0), len(in1))
	n = (n / rate168) * rate168
	for off := 0; off < n; off += rate168 {
		var in2 = in0[off : off+rate168]
		var in3 = in1[off : off+rate168]
		validateStripe(1, len(in2))
		validateStripe(1, len(in3))
		full := rate168 >> 3
		for lane := range full {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(in2[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(in3[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State2) AbsorbFinal(tail0, tail1 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) >= rate168 {
		panic("keccak: invalid final tail length")
	}
	full := len(tail0) >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(tail0[base : base+8])
		s.a[lane][1] ^= binary.LittleEndian.Uint64(tail1[base : base+8])
	}
	if rem := len(tail0) & 7; rem != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(tail0[base : base+rem])
		s.a[full][1] ^= loadPartialLE(tail1[base : base+rem])
	}
	posLane := len(tail0) >> 3
	pos := len(tail0)
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	endLane := (rate168 - 1) >> 3
	end := rate168 - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
}

func (s *State4) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State4) FastLoopAbsorb168(in0, in1, in2, in3 []byte) int {
	n := min(min(len(in0), len(in1)), min(len(in2), len(in3)))
	n = (n / rate168) * rate168
	for off := 0; off < n; off += rate168 {
		var in4 = in0[off : off+rate168]
		var in5 = in1[off : off+rate168]
		var in6 = in2[off : off+rate168]
		var in7 = in3[off : off+rate168]
		validateStripe(1, len(in4))
		validateStripe(1, len(in5))
		validateStripe(1, len(in6))
		validateStripe(1, len(in7))
		full := rate168 >> 3
		for lane := range full {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(in4[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(in5[base : base+8])
			s.a[lane][2] ^= binary.LittleEndian.Uint64(in6[base : base+8])
			s.a[lane][3] ^= binary.LittleEndian.Uint64(in7[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State4) AbsorbFinal(tail0, tail1, tail2, tail3 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) != len(tail2) || len(tail0) != len(tail3) || len(tail0) >= rate168 {
		panic("keccak: invalid final tail length")
	}
	full := len(tail0) >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(tail0[base : base+8])
		s.a[lane][1] ^= binary.LittleEndian.Uint64(tail1[base : base+8])
		s.a[lane][2] ^= binary.LittleEndian.Uint64(tail2[base : base+8])
		s.a[lane][3] ^= binary.LittleEndian.Uint64(tail3[base : base+8])
	}
	if rem := len(tail0) & 7; rem != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(tail0[base : base+rem])
		s.a[full][1] ^= loadPartialLE(tail1[base : base+rem])
		s.a[full][2] ^= loadPartialLE(tail2[base : base+rem])
		s.a[full][3] ^= loadPartialLE(tail3[base : base+rem])
	}
	posLane := len(tail0) >> 3
	pos := len(tail0)
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	xorByteInWord(&s.a[posLane][2], pos, ds)
	xorByteInWord(&s.a[posLane][3], pos, ds)
	endLane := (rate168 - 1) >> 3
	end := rate168 - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
	xorByteInWord(&s.a[endLane][2], end, 0x80)
	xorByteInWord(&s.a[endLane][3], end, 0x80)
}

func (s *State8) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State8) FastLoopAbsorb168(in0, in1, in2, in3, in4, in5, in6, in7 []byte) int {
	n := min(
		min(min(len(in0), len(in1)), min(len(in2), len(in3))),
		min(min(len(in4), len(in5)), min(len(in6), len(in7))),
	)
	n = (n / rate168) * rate168
	for off := 0; off < n; off += rate168 {
		var in8 = in0[off : off+rate168]
		var in9 = in1[off : off+rate168]
		var in10 = in2[off : off+rate168]
		var in11 = in3[off : off+rate168]
		var in12 = in4[off : off+rate168]
		var in13 = in5[off : off+rate168]
		var in14 = in6[off : off+rate168]
		var in15 = in7[off : off+rate168]
		validateStripe(1, len(in8))
		validateStripe(1, len(in9))
		validateStripe(1, len(in10))
		validateStripe(1, len(in11))
		validateStripe(1, len(in12))
		validateStripe(1, len(in13))
		validateStripe(1, len(in14))
		validateStripe(1, len(in15))
		full := rate168 >> 3
		for lane := range full {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(in8[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(in9[base : base+8])
			s.a[lane][2] ^= binary.LittleEndian.Uint64(in10[base : base+8])
			s.a[lane][3] ^= binary.LittleEndian.Uint64(in11[base : base+8])
			s.a[lane][4] ^= binary.LittleEndian.Uint64(in12[base : base+8])
			s.a[lane][5] ^= binary.LittleEndian.Uint64(in13[base : base+8])
			s.a[lane][6] ^= binary.LittleEndian.Uint64(in14[base : base+8])
			s.a[lane][7] ^= binary.LittleEndian.Uint64(in15[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State8) AbsorbFinal(tail0, tail1, tail2, tail3, tail4, tail5, tail6, tail7 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) != len(tail2) || len(tail0) != len(tail3) ||
		len(tail0) != len(tail4) || len(tail0) != len(tail5) || len(tail0) != len(tail6) ||
		len(tail0) != len(tail7) || len(tail0) >= rate168 {
		panic("keccak: invalid final tail length")
	}
	full := len(tail0) >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(tail0[base : base+8])
		s.a[lane][1] ^= binary.LittleEndian.Uint64(tail1[base : base+8])
		s.a[lane][2] ^= binary.LittleEndian.Uint64(tail2[base : base+8])
		s.a[lane][3] ^= binary.LittleEndian.Uint64(tail3[base : base+8])
		s.a[lane][4] ^= binary.LittleEndian.Uint64(tail4[base : base+8])
		s.a[lane][5] ^= binary.LittleEndian.Uint64(tail5[base : base+8])
		s.a[lane][6] ^= binary.LittleEndian.Uint64(tail6[base : base+8])
		s.a[lane][7] ^= binary.LittleEndian.Uint64(tail7[base : base+8])
	}
	if rem := len(tail0) & 7; rem != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(tail0[base : base+rem])
		s.a[full][1] ^= loadPartialLE(tail1[base : base+rem])
		s.a[full][2] ^= loadPartialLE(tail2[base : base+rem])
		s.a[full][3] ^= loadPartialLE(tail3[base : base+rem])
		s.a[full][4] ^= loadPartialLE(tail4[base : base+rem])
		s.a[full][5] ^= loadPartialLE(tail5[base : base+rem])
		s.a[full][6] ^= loadPartialLE(tail6[base : base+rem])
		s.a[full][7] ^= loadPartialLE(tail7[base : base+rem])
	}
	posLane := len(tail0) >> 3
	pos := len(tail0)
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	xorByteInWord(&s.a[posLane][2], pos, ds)
	xorByteInWord(&s.a[posLane][3], pos, ds)
	xorByteInWord(&s.a[posLane][4], pos, ds)
	xorByteInWord(&s.a[posLane][5], pos, ds)
	xorByteInWord(&s.a[posLane][6], pos, ds)
	xorByteInWord(&s.a[posLane][7], pos, ds)
	endLane := (rate168 - 1) >> 3
	end := rate168 - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
	xorByteInWord(&s.a[endLane][2], end, 0x80)
	xorByteInWord(&s.a[endLane][3], end, 0x80)
	xorByteInWord(&s.a[endLane][4], end, 0x80)
	xorByteInWord(&s.a[endLane][5], end, 0x80)
	xorByteInWord(&s.a[endLane][6], end, 0x80)
	xorByteInWord(&s.a[endLane][7], end, 0x80)
}
