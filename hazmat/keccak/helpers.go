package keccak

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
	for i := range rate {
		s.setByte(i, s.getByte(i)^in[i])
	}
}

func (s *State1) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 1, len(in))
	for i := range rate {
		s.setByte(i, in[i])
	}
}

func (s *State1) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 1, len(out))
	for i := range rate {
		out[i] = s.getByte(i)
	}
}

func (s *State1) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 1, len(dst))
	validateStripe(rate, 1, len(src))
	for i := range rate {
		v := src[i] ^ s.getByte(i)
		dst[i] = v
		s.setByte(i, v)
	}
}

func (s *State1) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 1, len(dst))
	validateStripe(rate, 1, len(src))
	for i := range rate {
		dst[i] = src[i] ^ s.getByte(i)
		s.setByte(i, src[i])
	}
}

func (s *State2) Reset() { clear(s.a[:]) }

func (s *State2) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 2, len(in))
	for inst := range 2 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, s.getByte(inst, i)^in[base+i])
		}
	}
}

func (s *State2) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 2, len(in))
	for inst := range 2 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, in[base+i])
		}
	}
}

func (s *State2) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 2, len(out))
	for inst := range 2 {
		base := inst * rate
		for i := range rate {
			out[base+i] = s.getByte(inst, i)
		}
	}
}

func (s *State2) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 2, len(dst))
	validateStripe(rate, 2, len(src))
	for inst := range 2 {
		base := inst * rate
		for i := range rate {
			v := src[base+i] ^ s.getByte(inst, i)
			dst[base+i] = v
			s.setByte(inst, i, v)
		}
	}
}

func (s *State2) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 2, len(dst))
	validateStripe(rate, 2, len(src))
	for inst := range 2 {
		base := inst * rate
		for i := range rate {
			dst[base+i] = src[base+i] ^ s.getByte(inst, i)
			s.setByte(inst, i, src[base+i])
		}
	}
}

func (s *State4) Reset() { clear(s.a[:]) }

func (s *State4) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 4, len(in))
	for inst := range 4 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, s.getByte(inst, i)^in[base+i])
		}
	}
}

func (s *State4) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 4, len(in))
	for inst := range 4 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, in[base+i])
		}
	}
}

func (s *State4) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 4, len(out))
	for inst := range 4 {
		base := inst * rate
		for i := range rate {
			out[base+i] = s.getByte(inst, i)
		}
	}
}

func (s *State4) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 4, len(dst))
	validateStripe(rate, 4, len(src))
	for inst := range 4 {
		base := inst * rate
		for i := range rate {
			v := src[base+i] ^ s.getByte(inst, i)
			dst[base+i] = v
			s.setByte(inst, i, v)
		}
	}
}

func (s *State4) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 4, len(dst))
	validateStripe(rate, 4, len(src))
	for inst := range 4 {
		base := inst * rate
		for i := range rate {
			dst[base+i] = src[base+i] ^ s.getByte(inst, i)
			s.setByte(inst, i, src[base+i])
		}
	}
}

func (s *State8) Reset() { clear(s.a[:]) }

func (s *State8) AbsorbStripe(rate int, in []byte) {
	validateStripe(rate, 8, len(in))
	for inst := range 8 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, s.getByte(inst, i)^in[base+i])
		}
	}
}

func (s *State8) OverwriteStripe(rate int, in []byte) {
	validateStripe(rate, 8, len(in))
	for inst := range 8 {
		base := inst * rate
		for i := range rate {
			s.setByte(inst, i, in[base+i])
		}
	}
}

func (s *State8) SqueezeStripe(rate int, out []byte) {
	validateStripe(rate, 8, len(out))
	for inst := range 8 {
		base := inst * rate
		for i := range rate {
			out[base+i] = s.getByte(inst, i)
		}
	}
}

func (s *State8) OverwriteEncryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 8, len(dst))
	validateStripe(rate, 8, len(src))
	for inst := range 8 {
		base := inst * rate
		for i := range rate {
			v := src[base+i] ^ s.getByte(inst, i)
			dst[base+i] = v
			s.setByte(inst, i, v)
		}
	}
}

func (s *State8) OverwriteDecryptStripe(rate int, dst, src []byte) {
	validateStripe(rate, 8, len(dst))
	validateStripe(rate, 8, len(src))
	for inst := range 8 {
		base := inst * rate
		for i := range rate {
			dst[base+i] = src[base+i] ^ s.getByte(inst, i)
			s.setByte(inst, i, src[base+i])
		}
	}
}
