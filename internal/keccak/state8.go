package keccak

import "encoding/binary"

// State8 is eight lane-major Keccak-p[1600] states with shared duplex position tracking.
type State8 struct {
	a   [lanes][8]uint64
	pos int
}

func permute12x8Generic(s *State8) {
	var t State1
	for inst := range 8 {
		for lane := range lanes {
			t.a[lane] = s.a[lane][inst]
		}
		keccakP1600x12(&t.a)
		for lane := range lanes {
			s.a[lane][inst] = t.a[lane]
		}
	}
}

func (s *State8) Permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
}

func (s *State8) Reset() {
	clear(s.a[:])
	s.pos = 0
}

// SetAll sets all 8 instances to be identical copies of base.
func (s *State8) SetAll(base *State1) {
	for lane := range lanes {
		for inst := range 8 {
			s.a[lane][inst] = base.a[lane]
		}
	}
	s.pos = base.pos
}

// AbsorbWords XORs words[i] into instance i at the current byte position,
// encoding each word as 8 little-endian bytes.
func (s *State8) AbsorbWords(words [8]uint64) {
	byteInLane := s.pos & 7
	laneIdx := s.pos >> 3
	if byteInLane == 0 {
		for inst := range 8 {
			s.a[laneIdx][inst] ^= words[inst]
		}
	} else {
		shift := uint(byteInLane) * 8
		for inst := range 8 {
			s.a[laneIdx][inst] ^= words[inst] << shift
			s.a[laneIdx+1][inst] ^= words[inst] >> (64 - shift)
		}
	}
	s.pos += 8
}

// fastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State8) fastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-7*stride, 0) // last instance starts at in[7*stride:]
	n = (n / Rate) * Rate
	if n > 0 && fastLoopAbsorb168x8Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		p0 := (*[Rate]byte)(in[off : off+Rate])
		p1 := (*[Rate]byte)(in[stride+off : stride+off+Rate])
		p2 := (*[Rate]byte)(in[2*stride+off : 2*stride+off+Rate])
		p3 := (*[Rate]byte)(in[3*stride+off : 3*stride+off+Rate])
		p4 := (*[Rate]byte)(in[4*stride+off : 4*stride+off+Rate])
		p5 := (*[Rate]byte)(in[5*stride+off : 5*stride+off+Rate])
		p6 := (*[Rate]byte)(in[6*stride+off : 6*stride+off+Rate])
		p7 := (*[Rate]byte)(in[7*stride+off : 7*stride+off+Rate])
		for lane := range Rate >> 3 {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(p0[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(p1[base : base+8])
			s.a[lane][2] ^= binary.LittleEndian.Uint64(p2[base : base+8])
			s.a[lane][3] ^= binary.LittleEndian.Uint64(p3[base : base+8])
			s.a[lane][4] ^= binary.LittleEndian.Uint64(p4[base : base+8])
			s.a[lane][5] ^= binary.LittleEndian.Uint64(p5[base : base+8])
			s.a[lane][6] ^= binary.LittleEndian.Uint64(p6[base : base+8])
			s.a[lane][7] ^= binary.LittleEndian.Uint64(p7[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// absorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State8) absorbFinal(tail0, tail1, tail2, tail3, tail4, tail5, tail6, tail7 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) != len(tail2) || len(tail0) != len(tail3) ||
		len(tail0) != len(tail4) || len(tail0) != len(tail5) || len(tail0) != len(tail6) ||
		len(tail0) != len(tail7) || len(tail0) >= Rate {
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
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	for inst := range 8 {
		xorByteInWord(&s.a[posLane][inst], pos, ds)
		xorByteInWord(&s.a[endLane][inst], end, 0x80)
	}
}

// fastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes.
func (s *State8) fastLoopEncrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopEncrypt168x8Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 8 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		s.Permute12()
	}
	return n
}

// fastLoopDecrypt168 decrypts ciphertext and permutes.
func (s *State8) fastLoopDecrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopDecrypt168x8Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 8 {
				ct := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				pt := ct ^ s.a[lane][inst]
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], pt)
				s.a[lane][inst] = ct
			}
		}
		s.Permute12()
	}
	return n
}

// PadPermute applies pad10*1 padding (ds at s.pos, 0x80 at Rate-1) and permutes all instances.
func (s *State8) PadPermute(ds byte) {
	shift := uint((s.pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := s.pos >> 3
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	for inst := range 8 {
		s.a[posLane][inst] ^= dsMask
		s.a[endLane][inst] ^= endMask
	}
	s.Permute12()
	s.pos = 0
}

// encryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State8) encryptBytes(inst int, src, dst []byte) {
	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		w := binary.LittleEndian.Uint64(src[base : base+8])
		s.a[i][inst] ^= w
		binary.LittleEndian.PutUint64(dst[base:base+8], s.a[i][inst])
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		w := loadPartialLE(src[base : base+rem])
		s.a[full][inst] ^= w
		storePartialLE(dst[base:base+rem], s.a[full][inst])
	}
}

// decryptBytes performs SpongeWrap decryption on a partial block for instance inst.
func (s *State8) decryptBytes(inst int, src, dst []byte) {
	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		ct := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct^s.a[i][inst])
		s.a[i][inst] = ct
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		ct := loadPartialLE(src[base : base+rem])
		mask := uint64(1)<<(rem*8) - 1
		storePartialLE(dst[base:base+rem], ct^(s.a[full][inst]&mask))
		s.a[full][inst] = (s.a[full][inst] & ^mask) | ct
	}
}

// AbsorbAll absorbs all data (8 instances at stride), applies padding with ds, and permutes.
func (s *State8) AbsorbAll(in []byte, stride int, ds byte) {
	done := s.fastLoopAbsorb168(in, stride)
	s.absorbFinal(
		in[done:stride],
		in[stride+done:2*stride],
		in[2*stride+done:3*stride],
		in[3*stride+done:4*stride],
		in[4*stride+done:5*stride],
		in[5*stride+done:6*stride],
		in[6*stride+done:7*stride],
		in[7*stride+done:8*stride],
		ds,
	)
	s.Permute12()
	s.pos = 0
}

// EncryptAll encrypts all of src into dst (8 instances at stride), applies padding with ds, and permutes.
func (s *State8) EncryptAll(src, dst []byte, stride int, ds byte) {
	done := s.fastLoopEncrypt168(src, dst, stride)
	tail := stride - done
	if tail > 0 {
		for inst := range 8 {
			off := inst*stride + done
			s.encryptBytes(inst, src[off:off+tail], dst[off:off+tail])
		}
	}
	s.pos = tail
	s.PadPermute(ds)
}

// DecryptAll decrypts all of src into dst (8 instances at stride), applies padding with ds, and permutes.
func (s *State8) DecryptAll(src, dst []byte, stride int, ds byte) {
	done := s.fastLoopDecrypt168(src, dst, stride)
	tail := stride - done
	if tail > 0 {
		for inst := range 8 {
			off := inst*stride + done
			s.decryptBytes(inst, src[off:off+tail], dst[off:off+tail])
		}
	}
	s.pos = tail
	s.PadPermute(ds)
}
