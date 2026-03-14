package keccak

import "encoding/binary"

// state8 is eight lane-major Keccak-p[1600] states with shared duplex position tracking.
type state8 struct {
	a   [lanes][8]uint64
	pos int
}

func permute12x8Generic(s *state8) {
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

func (s *state8) permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
}

func (s *state8) reset() {
	clear(s.a[:])
	s.pos = 0
}

// SetAll sets all 8 instances to be identical copies of base.
func (s *state8) setAll(base *State1) {
	for lane := range lanes {
		for inst := range 8 {
			s.a[lane][inst] = base.a[lane]
		}
	}
	s.pos = base.pos
}

// AbsorbWords XORs words[i] into instance i at the current byte position,
// encoding each word as 8 little-endian bytes.
func (s *state8) absorbWords(words [8]uint64) {
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

// fastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes.
func (s *state8) fastLoopEncrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate) * Rate
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 8 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		s.permute12()
	}
	return n
}

// fastLoopDecrypt168 decrypts ciphertext and permutes.
func (s *state8) fastLoopDecrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate) * Rate
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
		s.permute12()
	}
	return n
}

// PadPermute applies pad10*1 padding (ds at s.pos, 0x80 at Rate-1) and permutes all instances.
func (s *state8) padPermute(ds byte) {
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
	s.permute12()
	s.pos = 0
}

// encryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *state8) encryptBytes(inst int, src, dst []byte) {
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
func (s *state8) decryptBytes(inst int, src, dst []byte) {
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

// encryptAll encrypts all of src into dst (8 instances at stride), applies padding with ds, and permutes.
func (s *state8) encryptAll(src, dst []byte, stride int, ds byte) {
	done := s.fastLoopEncrypt168(src, dst, stride)
	tail := stride - done
	if tail > 0 {
		for inst := range 8 {
			off := inst*stride + done
			s.encryptBytes(inst, src[off:off+tail], dst[off:off+tail])
		}
	}
	s.pos = tail
	s.padPermute(ds)
}

// decryptAll decrypts all of src into dst (8 instances at stride), applies padding with ds, and permutes.
func (s *state8) decryptAll(src, dst []byte, stride int, ds byte) {
	done := s.fastLoopDecrypt168(src, dst, stride)
	tail := stride - done
	if tail > 0 {
		for inst := range 8 {
			off := inst*stride + done
			s.decryptBytes(inst, src[off:off+tail], dst[off:off+tail])
		}
	}
	s.pos = tail
	s.padPermute(ds)
}
