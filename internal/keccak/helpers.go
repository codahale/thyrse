package keccak

import "encoding/binary"

func validateRate(rate int) {
	if rate < 0 || rate > StateBytes {
		panic("keccak: invalid rate")
	}
}

func validateStripe(rate, width, n int) {
	validateRate(rate)
	if n != width*rate {
		panic("keccak: invalid stripe length")
	}
}

func lowMask(n int) uint64 {
	if n <= 0 {
		return 0
	}
	return (uint64(1) << (8 * n)) - 1
}

func loadPartialLE(in []byte) uint64 {
	var v uint64
	for i := range in {
		v |= uint64(in[i]) << (8 * i)
	}
	return v
}

func storePartialLE(out []byte, v uint64) {
	for i := range out {
		out[i] = byte(v >> (8 * i))
	}
}

func (s *State1) getByte(pos int) byte {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	return byte(s.a[lane] >> shift)
}

func (s *State1) setByte(pos int, v byte) {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	mask := uint64(0xFF) << shift
	s.a[lane] = (s.a[lane] &^ mask) | (uint64(v) << shift)
}

func (s *State2) getByte(inst, pos int) byte {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	return byte(s.a[lane][inst] >> shift)
}

func (s *State2) setByte(inst, pos int, v byte) {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	mask := uint64(0xFF) << shift
	s.a[lane][inst] = (s.a[lane][inst] &^ mask) | (uint64(v) << shift)
}

func (s *State4) getByte(inst, pos int) byte {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	return byte(s.a[lane][inst] >> shift)
}

func (s *State4) setByte(inst, pos int, v byte) {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	mask := uint64(0xFF) << shift
	s.a[lane][inst] = (s.a[lane][inst] &^ mask) | (uint64(v) << shift)
}

func (s *State8) getByte(inst, pos int) byte {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	return byte(s.a[lane][inst] >> shift)
}

func (s *State8) setByte(inst, pos int, v byte) {
	lane := pos >> 3
	shift := uint((pos & 7) << 3)
	mask := uint64(0xFF) << shift
	s.a[lane][inst] = (s.a[lane][inst] &^ mask) | (uint64(v) << shift)
}

func (s *State1) Reset() { clear(s.a[:]) }

func (s *State1) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 1, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane] ^= binary.LittleEndian.Uint64(in[base : base+8])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		s.a[full] ^= loadPartialLE(in[base : base+tail])
	}
}

func (s *State1) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 1, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane] = binary.LittleEndian.Uint64(in[base : base+8])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		mask := lowMask(tail)
		v := loadPartialLE(in[base : base+tail])
		s.a[full] = (s.a[full] &^ mask) | (v & mask)
	}
}

func (s *State1) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 1, len(out))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		storePartialLE(out[base:base+tail], s.a[full])
	}
}

func (s *State1) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 1, len(dst))
	validateStripe(rate, 1, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		v := binary.LittleEndian.Uint64(src[base:base+8]) ^ s.a[lane]
		binary.LittleEndian.PutUint64(dst[base:base+8], v)
		s.a[lane] = v
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		mask := lowMask(tail)
		st := s.a[full]
		srcLo := loadPartialLE(src[base : base+tail])
		ctLo := (srcLo ^ st) & mask
		storePartialLE(dst[base:base+tail], ctLo)
		s.a[full] = (st &^ mask) | ctLo
	}
}

func (s *State1) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 1, len(dst))
	validateStripe(rate, 1, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		ct := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct^s.a[lane])
		s.a[lane] = ct
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		mask := lowMask(tail)
		st := s.a[full]
		ctLo := loadPartialLE(src[base : base+tail])
		ptLo := (ctLo ^ st) & mask
		storePartialLE(dst[base:base+tail], ptLo)
		s.a[full] = (st &^ mask) | (ctLo & mask)
	}
}

func (s *State2) Reset() { clear(s.a[:]) }

func (s *State2) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 2, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] ^= binary.LittleEndian.Uint64(in[o1 : o1+8])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(in[base : base+tail])
		o1 := rate + base
		s.a[full][1] ^= loadPartialLE(in[o1 : o1+tail])
	}
}

func (s *State2) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 2, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] = binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] = binary.LittleEndian.Uint64(in[o1 : o1+8])
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		v0 := loadPartialLE(in[base : base+tail])
		s.a[full][0] = (s.a[full][0] &^ mask) | (v0 & mask)
		o1 := rate + base
		v1 := loadPartialLE(in[o1 : o1+tail])
		s.a[full][1] = (s.a[full][1] &^ mask) | (v1 & mask)
	}
}

func (s *State2) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 2, len(out))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane][0])
		o1 := rate + base
		binary.LittleEndian.PutUint64(out[o1:o1+8], s.a[lane][1])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		storePartialLE(out[base:base+tail], s.a[full][0])
		o1 := rate + base
		storePartialLE(out[o1:o1+tail], s.a[full][1])
	}
}

func (s *State2) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 2, len(dst))
	validateStripe(rate, 2, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		v0 := binary.LittleEndian.Uint64(src[base:base+8]) ^ s.a[lane][0]
		binary.LittleEndian.PutUint64(dst[base:base+8], v0)
		s.a[lane][0] = v0

		o1 := rate + base
		v1 := binary.LittleEndian.Uint64(src[o1:o1+8]) ^ s.a[lane][1]
		binary.LittleEndian.PutUint64(dst[o1:o1+8], v1)
		s.a[lane][1] = v1
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		st0 := s.a[full][0]
		src0 := loadPartialLE(src[base : base+tail])
		ct0 := (src0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], ct0)
		s.a[full][0] = (st0 &^ mask) | ct0

		o1 := rate + base
		st1 := s.a[full][1]
		src1 := loadPartialLE(src[o1 : o1+tail])
		ct1 := (src1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], ct1)
		s.a[full][1] = (st1 &^ mask) | ct1
	}
}

func (s *State2) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 2, len(dst))
	validateStripe(rate, 2, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		ct0 := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct0^s.a[lane][0])
		s.a[lane][0] = ct0

		o1 := rate + base
		ct1 := binary.LittleEndian.Uint64(src[o1 : o1+8])
		binary.LittleEndian.PutUint64(dst[o1:o1+8], ct1^s.a[lane][1])
		s.a[lane][1] = ct1
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		st0 := s.a[full][0]
		ct0 := loadPartialLE(src[base : base+tail])
		pt0 := (ct0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], pt0)
		s.a[full][0] = (st0 &^ mask) | (ct0 & mask)

		o1 := rate + base
		st1 := s.a[full][1]
		ct1 := loadPartialLE(src[o1 : o1+tail])
		pt1 := (ct1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], pt1)
		s.a[full][1] = (st1 &^ mask) | (ct1 & mask)
	}
}

func (s *State4) Reset() { clear(s.a[:]) }

func (s *State4) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 4, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] ^= binary.LittleEndian.Uint64(in[o1 : o1+8])
		o2 := 2*rate + base
		s.a[lane][2] ^= binary.LittleEndian.Uint64(in[o2 : o2+8])
		o3 := 3*rate + base
		s.a[lane][3] ^= binary.LittleEndian.Uint64(in[o3 : o3+8])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(in[base : base+tail])
		o1 := rate + base
		s.a[full][1] ^= loadPartialLE(in[o1 : o1+tail])
		o2 := 2*rate + base
		s.a[full][2] ^= loadPartialLE(in[o2 : o2+tail])
		o3 := 3*rate + base
		s.a[full][3] ^= loadPartialLE(in[o3 : o3+tail])
	}
}

func (s *State4) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 4, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] = binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] = binary.LittleEndian.Uint64(in[o1 : o1+8])
		o2 := 2*rate + base
		s.a[lane][2] = binary.LittleEndian.Uint64(in[o2 : o2+8])
		o3 := 3*rate + base
		s.a[lane][3] = binary.LittleEndian.Uint64(in[o3 : o3+8])
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		v0 := loadPartialLE(in[base : base+tail])
		s.a[full][0] = (s.a[full][0] &^ mask) | (v0 & mask)
		o1 := rate + base
		v1 := loadPartialLE(in[o1 : o1+tail])
		s.a[full][1] = (s.a[full][1] &^ mask) | (v1 & mask)
		o2 := 2*rate + base
		v2 := loadPartialLE(in[o2 : o2+tail])
		s.a[full][2] = (s.a[full][2] &^ mask) | (v2 & mask)
		o3 := 3*rate + base
		v3 := loadPartialLE(in[o3 : o3+tail])
		s.a[full][3] = (s.a[full][3] &^ mask) | (v3 & mask)
	}
}

func (s *State4) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 4, len(out))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane][0])
		o1 := rate + base
		binary.LittleEndian.PutUint64(out[o1:o1+8], s.a[lane][1])
		o2 := 2*rate + base
		binary.LittleEndian.PutUint64(out[o2:o2+8], s.a[lane][2])
		o3 := 3*rate + base
		binary.LittleEndian.PutUint64(out[o3:o3+8], s.a[lane][3])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		storePartialLE(out[base:base+tail], s.a[full][0])
		o1 := rate + base
		storePartialLE(out[o1:o1+tail], s.a[full][1])
		o2 := 2*rate + base
		storePartialLE(out[o2:o2+tail], s.a[full][2])
		o3 := 3*rate + base
		storePartialLE(out[o3:o3+tail], s.a[full][3])
	}
}

func (s *State4) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 4, len(dst))
	validateStripe(rate, 4, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		v0 := binary.LittleEndian.Uint64(src[base:base+8]) ^ s.a[lane][0]
		binary.LittleEndian.PutUint64(dst[base:base+8], v0)
		s.a[lane][0] = v0

		o1 := rate + base
		v1 := binary.LittleEndian.Uint64(src[o1:o1+8]) ^ s.a[lane][1]
		binary.LittleEndian.PutUint64(dst[o1:o1+8], v1)
		s.a[lane][1] = v1

		o2 := 2*rate + base
		v2 := binary.LittleEndian.Uint64(src[o2:o2+8]) ^ s.a[lane][2]
		binary.LittleEndian.PutUint64(dst[o2:o2+8], v2)
		s.a[lane][2] = v2

		o3 := 3*rate + base
		v3 := binary.LittleEndian.Uint64(src[o3:o3+8]) ^ s.a[lane][3]
		binary.LittleEndian.PutUint64(dst[o3:o3+8], v3)
		s.a[lane][3] = v3
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3

		st0 := s.a[full][0]
		src0 := loadPartialLE(src[base : base+tail])
		ct0 := (src0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], ct0)
		s.a[full][0] = (st0 &^ mask) | ct0

		o1 := rate + base
		st1 := s.a[full][1]
		src1 := loadPartialLE(src[o1 : o1+tail])
		ct1 := (src1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], ct1)
		s.a[full][1] = (st1 &^ mask) | ct1

		o2 := 2*rate + base
		st2 := s.a[full][2]
		src2 := loadPartialLE(src[o2 : o2+tail])
		ct2 := (src2 ^ st2) & mask
		storePartialLE(dst[o2:o2+tail], ct2)
		s.a[full][2] = (st2 &^ mask) | ct2

		o3 := 3*rate + base
		st3 := s.a[full][3]
		src3 := loadPartialLE(src[o3 : o3+tail])
		ct3 := (src3 ^ st3) & mask
		storePartialLE(dst[o3:o3+tail], ct3)
		s.a[full][3] = (st3 &^ mask) | ct3
	}
}

func (s *State4) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 4, len(dst))
	validateStripe(rate, 4, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		ct0 := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct0^s.a[lane][0])
		s.a[lane][0] = ct0

		o1 := rate + base
		ct1 := binary.LittleEndian.Uint64(src[o1 : o1+8])
		binary.LittleEndian.PutUint64(dst[o1:o1+8], ct1^s.a[lane][1])
		s.a[lane][1] = ct1

		o2 := 2*rate + base
		ct2 := binary.LittleEndian.Uint64(src[o2 : o2+8])
		binary.LittleEndian.PutUint64(dst[o2:o2+8], ct2^s.a[lane][2])
		s.a[lane][2] = ct2

		o3 := 3*rate + base
		ct3 := binary.LittleEndian.Uint64(src[o3 : o3+8])
		binary.LittleEndian.PutUint64(dst[o3:o3+8], ct3^s.a[lane][3])
		s.a[lane][3] = ct3
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3

		st0 := s.a[full][0]
		ct0 := loadPartialLE(src[base : base+tail])
		pt0 := (ct0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], pt0)
		s.a[full][0] = (st0 &^ mask) | (ct0 & mask)

		o1 := rate + base
		st1 := s.a[full][1]
		ct1 := loadPartialLE(src[o1 : o1+tail])
		pt1 := (ct1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], pt1)
		s.a[full][1] = (st1 &^ mask) | (ct1 & mask)

		o2 := 2*rate + base
		st2 := s.a[full][2]
		ct2 := loadPartialLE(src[o2 : o2+tail])
		pt2 := (ct2 ^ st2) & mask
		storePartialLE(dst[o2:o2+tail], pt2)
		s.a[full][2] = (st2 &^ mask) | (ct2 & mask)

		o3 := 3*rate + base
		st3 := s.a[full][3]
		ct3 := loadPartialLE(src[o3 : o3+tail])
		pt3 := (ct3 ^ st3) & mask
		storePartialLE(dst[o3:o3+tail], pt3)
		s.a[full][3] = (st3 &^ mask) | (ct3 & mask)
	}
}

func (s *State8) Reset() { clear(s.a[:]) }

func (s *State8) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 8, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] ^= binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] ^= binary.LittleEndian.Uint64(in[o1 : o1+8])
		o2 := 2*rate + base
		s.a[lane][2] ^= binary.LittleEndian.Uint64(in[o2 : o2+8])
		o3 := 3*rate + base
		s.a[lane][3] ^= binary.LittleEndian.Uint64(in[o3 : o3+8])
		o4 := 4*rate + base
		s.a[lane][4] ^= binary.LittleEndian.Uint64(in[o4 : o4+8])
		o5 := 5*rate + base
		s.a[lane][5] ^= binary.LittleEndian.Uint64(in[o5 : o5+8])
		o6 := 6*rate + base
		s.a[lane][6] ^= binary.LittleEndian.Uint64(in[o6 : o6+8])
		o7 := 7*rate + base
		s.a[lane][7] ^= binary.LittleEndian.Uint64(in[o7 : o7+8])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		s.a[full][0] ^= loadPartialLE(in[base : base+tail])
		o1 := rate + base
		s.a[full][1] ^= loadPartialLE(in[o1 : o1+tail])
		o2 := 2*rate + base
		s.a[full][2] ^= loadPartialLE(in[o2 : o2+tail])
		o3 := 3*rate + base
		s.a[full][3] ^= loadPartialLE(in[o3 : o3+tail])
		o4 := 4*rate + base
		s.a[full][4] ^= loadPartialLE(in[o4 : o4+tail])
		o5 := 5*rate + base
		s.a[full][5] ^= loadPartialLE(in[o5 : o5+tail])
		o6 := 6*rate + base
		s.a[full][6] ^= loadPartialLE(in[o6 : o6+tail])
		o7 := 7*rate + base
		s.a[full][7] ^= loadPartialLE(in[o7 : o7+tail])
	}
}

func (s *State8) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 8, len(in))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		s.a[lane][0] = binary.LittleEndian.Uint64(in[base : base+8])
		o1 := rate + base
		s.a[lane][1] = binary.LittleEndian.Uint64(in[o1 : o1+8])
		o2 := 2*rate + base
		s.a[lane][2] = binary.LittleEndian.Uint64(in[o2 : o2+8])
		o3 := 3*rate + base
		s.a[lane][3] = binary.LittleEndian.Uint64(in[o3 : o3+8])
		o4 := 4*rate + base
		s.a[lane][4] = binary.LittleEndian.Uint64(in[o4 : o4+8])
		o5 := 5*rate + base
		s.a[lane][5] = binary.LittleEndian.Uint64(in[o5 : o5+8])
		o6 := 6*rate + base
		s.a[lane][6] = binary.LittleEndian.Uint64(in[o6 : o6+8])
		o7 := 7*rate + base
		s.a[lane][7] = binary.LittleEndian.Uint64(in[o7 : o7+8])
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		v0 := loadPartialLE(in[base : base+tail])
		s.a[full][0] = (s.a[full][0] &^ mask) | (v0 & mask)
		o1 := rate + base
		v1 := loadPartialLE(in[o1 : o1+tail])
		s.a[full][1] = (s.a[full][1] &^ mask) | (v1 & mask)
		o2 := 2*rate + base
		v2 := loadPartialLE(in[o2 : o2+tail])
		s.a[full][2] = (s.a[full][2] &^ mask) | (v2 & mask)
		o3 := 3*rate + base
		v3 := loadPartialLE(in[o3 : o3+tail])
		s.a[full][3] = (s.a[full][3] &^ mask) | (v3 & mask)
		o4 := 4*rate + base
		v4 := loadPartialLE(in[o4 : o4+tail])
		s.a[full][4] = (s.a[full][4] &^ mask) | (v4 & mask)
		o5 := 5*rate + base
		v5 := loadPartialLE(in[o5 : o5+tail])
		s.a[full][5] = (s.a[full][5] &^ mask) | (v5 & mask)
		o6 := 6*rate + base
		v6 := loadPartialLE(in[o6 : o6+tail])
		s.a[full][6] = (s.a[full][6] &^ mask) | (v6 & mask)
		o7 := 7*rate + base
		v7 := loadPartialLE(in[o7 : o7+tail])
		s.a[full][7] = (s.a[full][7] &^ mask) | (v7 & mask)
	}
}

func (s *State8) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 8, len(out))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		binary.LittleEndian.PutUint64(out[base:base+8], s.a[lane][0])
		o1 := rate + base
		binary.LittleEndian.PutUint64(out[o1:o1+8], s.a[lane][1])
		o2 := 2*rate + base
		binary.LittleEndian.PutUint64(out[o2:o2+8], s.a[lane][2])
		o3 := 3*rate + base
		binary.LittleEndian.PutUint64(out[o3:o3+8], s.a[lane][3])
		o4 := 4*rate + base
		binary.LittleEndian.PutUint64(out[o4:o4+8], s.a[lane][4])
		o5 := 5*rate + base
		binary.LittleEndian.PutUint64(out[o5:o5+8], s.a[lane][5])
		o6 := 6*rate + base
		binary.LittleEndian.PutUint64(out[o6:o6+8], s.a[lane][6])
		o7 := 7*rate + base
		binary.LittleEndian.PutUint64(out[o7:o7+8], s.a[lane][7])
	}
	if tail := rate & 7; tail != 0 {
		base := full << 3
		storePartialLE(out[base:base+tail], s.a[full][0])
		o1 := rate + base
		storePartialLE(out[o1:o1+tail], s.a[full][1])
		o2 := 2*rate + base
		storePartialLE(out[o2:o2+tail], s.a[full][2])
		o3 := 3*rate + base
		storePartialLE(out[o3:o3+tail], s.a[full][3])
		o4 := 4*rate + base
		storePartialLE(out[o4:o4+tail], s.a[full][4])
		o5 := 5*rate + base
		storePartialLE(out[o5:o5+tail], s.a[full][5])
		o6 := 6*rate + base
		storePartialLE(out[o6:o6+tail], s.a[full][6])
		o7 := 7*rate + base
		storePartialLE(out[o7:o7+tail], s.a[full][7])
	}
}

func (s *State8) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 8, len(dst))
	validateStripe(rate, 8, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		v0 := binary.LittleEndian.Uint64(src[base:base+8]) ^ s.a[lane][0]
		binary.LittleEndian.PutUint64(dst[base:base+8], v0)
		s.a[lane][0] = v0
		o1 := rate + base
		v1 := binary.LittleEndian.Uint64(src[o1:o1+8]) ^ s.a[lane][1]
		binary.LittleEndian.PutUint64(dst[o1:o1+8], v1)
		s.a[lane][1] = v1
		o2 := 2*rate + base
		v2 := binary.LittleEndian.Uint64(src[o2:o2+8]) ^ s.a[lane][2]
		binary.LittleEndian.PutUint64(dst[o2:o2+8], v2)
		s.a[lane][2] = v2
		o3 := 3*rate + base
		v3 := binary.LittleEndian.Uint64(src[o3:o3+8]) ^ s.a[lane][3]
		binary.LittleEndian.PutUint64(dst[o3:o3+8], v3)
		s.a[lane][3] = v3
		o4 := 4*rate + base
		v4 := binary.LittleEndian.Uint64(src[o4:o4+8]) ^ s.a[lane][4]
		binary.LittleEndian.PutUint64(dst[o4:o4+8], v4)
		s.a[lane][4] = v4
		o5 := 5*rate + base
		v5 := binary.LittleEndian.Uint64(src[o5:o5+8]) ^ s.a[lane][5]
		binary.LittleEndian.PutUint64(dst[o5:o5+8], v5)
		s.a[lane][5] = v5
		o6 := 6*rate + base
		v6 := binary.LittleEndian.Uint64(src[o6:o6+8]) ^ s.a[lane][6]
		binary.LittleEndian.PutUint64(dst[o6:o6+8], v6)
		s.a[lane][6] = v6
		o7 := 7*rate + base
		v7 := binary.LittleEndian.Uint64(src[o7:o7+8]) ^ s.a[lane][7]
		binary.LittleEndian.PutUint64(dst[o7:o7+8], v7)
		s.a[lane][7] = v7
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		st0 := s.a[full][0]
		src0 := loadPartialLE(src[base : base+tail])
		ct0 := (src0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], ct0)
		s.a[full][0] = (st0 &^ mask) | ct0
		o1 := rate + base
		st1 := s.a[full][1]
		src1 := loadPartialLE(src[o1 : o1+tail])
		ct1 := (src1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], ct1)
		s.a[full][1] = (st1 &^ mask) | ct1
		o2 := 2*rate + base
		st2 := s.a[full][2]
		src2 := loadPartialLE(src[o2 : o2+tail])
		ct2 := (src2 ^ st2) & mask
		storePartialLE(dst[o2:o2+tail], ct2)
		s.a[full][2] = (st2 &^ mask) | ct2
		o3 := 3*rate + base
		st3 := s.a[full][3]
		src3 := loadPartialLE(src[o3 : o3+tail])
		ct3 := (src3 ^ st3) & mask
		storePartialLE(dst[o3:o3+tail], ct3)
		s.a[full][3] = (st3 &^ mask) | ct3
		o4 := 4*rate + base
		st4 := s.a[full][4]
		src4 := loadPartialLE(src[o4 : o4+tail])
		ct4 := (src4 ^ st4) & mask
		storePartialLE(dst[o4:o4+tail], ct4)
		s.a[full][4] = (st4 &^ mask) | ct4
		o5 := 5*rate + base
		st5 := s.a[full][5]
		src5 := loadPartialLE(src[o5 : o5+tail])
		ct5 := (src5 ^ st5) & mask
		storePartialLE(dst[o5:o5+tail], ct5)
		s.a[full][5] = (st5 &^ mask) | ct5
		o6 := 6*rate + base
		st6 := s.a[full][6]
		src6 := loadPartialLE(src[o6 : o6+tail])
		ct6 := (src6 ^ st6) & mask
		storePartialLE(dst[o6:o6+tail], ct6)
		s.a[full][6] = (st6 &^ mask) | ct6
		o7 := 7*rate + base
		st7 := s.a[full][7]
		src7 := loadPartialLE(src[o7 : o7+tail])
		ct7 := (src7 ^ st7) & mask
		storePartialLE(dst[o7:o7+tail], ct7)
		s.a[full][7] = (st7 &^ mask) | ct7
	}
}

func (s *State8) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 8, len(dst))
	validateStripe(rate, 8, len(src))
	full := rate >> 3
	for lane := range full {
		base := lane << 3
		ct0 := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct0^s.a[lane][0])
		s.a[lane][0] = ct0
		o1 := rate + base
		ct1 := binary.LittleEndian.Uint64(src[o1 : o1+8])
		binary.LittleEndian.PutUint64(dst[o1:o1+8], ct1^s.a[lane][1])
		s.a[lane][1] = ct1
		o2 := 2*rate + base
		ct2 := binary.LittleEndian.Uint64(src[o2 : o2+8])
		binary.LittleEndian.PutUint64(dst[o2:o2+8], ct2^s.a[lane][2])
		s.a[lane][2] = ct2
		o3 := 3*rate + base
		ct3 := binary.LittleEndian.Uint64(src[o3 : o3+8])
		binary.LittleEndian.PutUint64(dst[o3:o3+8], ct3^s.a[lane][3])
		s.a[lane][3] = ct3
		o4 := 4*rate + base
		ct4 := binary.LittleEndian.Uint64(src[o4 : o4+8])
		binary.LittleEndian.PutUint64(dst[o4:o4+8], ct4^s.a[lane][4])
		s.a[lane][4] = ct4
		o5 := 5*rate + base
		ct5 := binary.LittleEndian.Uint64(src[o5 : o5+8])
		binary.LittleEndian.PutUint64(dst[o5:o5+8], ct5^s.a[lane][5])
		s.a[lane][5] = ct5
		o6 := 6*rate + base
		ct6 := binary.LittleEndian.Uint64(src[o6 : o6+8])
		binary.LittleEndian.PutUint64(dst[o6:o6+8], ct6^s.a[lane][6])
		s.a[lane][6] = ct6
		o7 := 7*rate + base
		ct7 := binary.LittleEndian.Uint64(src[o7 : o7+8])
		binary.LittleEndian.PutUint64(dst[o7:o7+8], ct7^s.a[lane][7])
		s.a[lane][7] = ct7
	}
	if tail := rate & 7; tail != 0 {
		mask := lowMask(tail)
		base := full << 3
		st0 := s.a[full][0]
		ct0 := loadPartialLE(src[base : base+tail])
		pt0 := (ct0 ^ st0) & mask
		storePartialLE(dst[base:base+tail], pt0)
		s.a[full][0] = (st0 &^ mask) | (ct0 & mask)
		o1 := rate + base
		st1 := s.a[full][1]
		ct1 := loadPartialLE(src[o1 : o1+tail])
		pt1 := (ct1 ^ st1) & mask
		storePartialLE(dst[o1:o1+tail], pt1)
		s.a[full][1] = (st1 &^ mask) | (ct1 & mask)
		o2 := 2*rate + base
		st2 := s.a[full][2]
		ct2 := loadPartialLE(src[o2 : o2+tail])
		pt2 := (ct2 ^ st2) & mask
		storePartialLE(dst[o2:o2+tail], pt2)
		s.a[full][2] = (st2 &^ mask) | (ct2 & mask)
		o3 := 3*rate + base
		st3 := s.a[full][3]
		ct3 := loadPartialLE(src[o3 : o3+tail])
		pt3 := (ct3 ^ st3) & mask
		storePartialLE(dst[o3:o3+tail], pt3)
		s.a[full][3] = (st3 &^ mask) | (ct3 & mask)
		o4 := 4*rate + base
		st4 := s.a[full][4]
		ct4 := loadPartialLE(src[o4 : o4+tail])
		pt4 := (ct4 ^ st4) & mask
		storePartialLE(dst[o4:o4+tail], pt4)
		s.a[full][4] = (st4 &^ mask) | (ct4 & mask)
		o5 := 5*rate + base
		st5 := s.a[full][5]
		ct5 := loadPartialLE(src[o5 : o5+tail])
		pt5 := (ct5 ^ st5) & mask
		storePartialLE(dst[o5:o5+tail], pt5)
		s.a[full][5] = (st5 &^ mask) | (ct5 & mask)
		o6 := 6*rate + base
		st6 := s.a[full][6]
		ct6 := loadPartialLE(src[o6 : o6+tail])
		pt6 := (ct6 ^ st6) & mask
		storePartialLE(dst[o6:o6+tail], pt6)
		s.a[full][6] = (st6 &^ mask) | (ct6 & mask)
		o7 := 7*rate + base
		st7 := s.a[full][7]
		ct7 := loadPartialLE(src[o7 : o7+tail])
		pt7 := (ct7 ^ st7) & mask
		storePartialLE(dst[o7:o7+tail], pt7)
		s.a[full][7] = (st7 &^ mask) | (ct7 & mask)
	}
}
