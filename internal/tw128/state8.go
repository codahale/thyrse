package tw128

import "encoding/binary"

// state8 is eight lane-major Keccak-p[1600] states with shared duplex position tracking.
type state8 struct {
	a   [lanes][8]uint64
	pos int
}

func permute12x8Generic(s *state8) {
	var t [lanes]uint64
	for inst := range 8 {
		for lane := range lanes {
			t[lane] = s.a[lane][inst]
		}
		keccakP1600x12(&t)
		for lane := range lanes {
			s.a[lane][inst] = t[lane]
		}
	}
}

func (s *state8) permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
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

// bodyEncryptAll8 encrypts all of src into dst (8 instances at stride) with capacity framing.
// Each rate block gets s.a[21][inst] ^= 0x01 before permute (body block framing).
func (s *state8) bodyEncryptAll8(src, dst []byte, stride int) {
	s.bodyFastLoopEncrypt168(src, dst, stride)
}

// bodyDecryptAll8 decrypts all of src into dst (8 instances at stride) with capacity framing.
func (s *state8) bodyDecryptAll8(src, dst []byte, stride int) {
	s.bodyFastLoopDecrypt168(src, dst, stride)
}

// bodyPadStarPermute applies pad10* and capacity framing to finalize a body
// phase across all 8 instances, then permutes and resets pos.
func (s *state8) bodyPadStarPermute() {
	for inst := range 8 {
		xorByteInWord(&s.a[s.pos>>3][inst], s.pos, 0x01)
		s.a[21][inst] ^= 0x01
	}
	s.permute12()
	s.pos = 0
}

// bodyFastLoopEncrypt168 encrypts full 168-byte stripes with capacity framing.
func (s *state8) bodyFastLoopEncrypt168(src, dst []byte, stride int) {
	n := max(len(src)-7*stride, 0)
	n = (n / rate) * rate
	for off := 0; off < n; off += rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 8 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		for inst := range 8 {
			s.a[21][inst] ^= 0x01
		}
		s.permute12()
	}
}

// bodyFastLoopDecrypt168 decrypts full 168-byte stripes with capacity framing.
func (s *state8) bodyFastLoopDecrypt168(src, dst []byte, stride int) {
	n := max(len(src)-7*stride, 0)
	n = (n / rate) * rate
	for off := 0; off < n; off += rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 8 {
				ct := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				pt := ct ^ s.a[lane][inst]
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], pt)
				s.a[lane][inst] = ct
			}
		}
		for inst := range 8 {
			s.a[21][inst] ^= 0x01
		}
		s.permute12()
	}
}
