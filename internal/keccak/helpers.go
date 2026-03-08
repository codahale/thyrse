package keccak

import "encoding/binary"

const (
	Rate = 168
)

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

func xorByteInWord(w *uint64, pos int, b byte) {
	shift := uint((pos & 7) << 3)
	*w ^= uint64(b) << shift
}

func (s *State1) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State1) FastLoopAbsorb168(in []byte) int {
	n := (len(in) / Rate) * Rate
	if n > 0 && fastLoopAbsorb168x1Arch(s, in[:n]) {
		return n
	}
	for off := 0; off < n; off += Rate {
		p := (*[Rate]byte)(in[off : off+Rate])
		for lane := range Rate >> 3 {
			base := lane << 3
			s.a[lane] ^= binary.LittleEndian.Uint64(p[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs a final partial 168-byte block and applies Keccak padding.
func (s *State1) AbsorbFinal(tail []byte, ds byte) {

	if len(tail) >= Rate {
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
	xorByteInWord(&s.a[(Rate-1)>>3], Rate-1, 0x80)
}

// FastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes
// for each full 168-byte block. Returns bytes processed (multiple of 168).
func (s *State1) FastLoopEncrypt168(src, dst []byte) int {
	n := (len(src) / Rate) * Rate
	if n > 0 && fastLoopEncrypt168x1Arch(s, src[:n], dst[:n]) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			w := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			s.a[lane] ^= w
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], s.a[lane])
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt168 decrypts ciphertext (plaintext = ct ^ state, state = ct), and permutes
// for each full 168-byte block. Returns bytes processed (multiple of 168).
func (s *State1) FastLoopDecrypt168(src, dst []byte) int {
	n := (len(src) / Rate) * Rate
	if n > 0 && fastLoopDecrypt168x1Arch(s, src[:n], dst[:n]) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			ct := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			pt := ct ^ s.a[lane]
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], pt)
			s.a[lane] = ct
		}
		s.Permute12()
	}
	return n
}

// PadPermute applies pad10*1 padding (ds at pos, 0x80 at Rate-1) and permutes.
func (s *State1) PadPermute(pos int, ds byte) {
	xorByteInWord(&s.a[pos>>3], pos, ds)
	xorByteInWord(&s.a[(Rate-1)>>3], Rate-1, 0x80)
	s.Permute12()
}

// ExtractBytes copies the first len(dst) bytes from the state.
func (s *State1) ExtractBytes(dst []byte) {
	full := len(dst) >> 3
	if full > 0 {
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		binary.LittleEndian.PutUint64(dst[i*8:i*8+8], s.a[i])
	}
	if rem := len(dst) & 7; rem > 0 {
		storePartialLE(dst[full*8:], s.a[full])
	}
}

// XORBytesAt XOR-absorbs data into the state starting at byte position pos.
// It does not apply padding or permute; the caller manages rate boundaries.
func (s *State1) XORBytesAt(pos int, data []byte) {
	lane := pos >> 3
	off := pos & 7

	if off != 0 {
		n := min(8-off, len(data))
		shift := uint(off) << 3
		s.a[lane] ^= loadPartialLE(data[:n]) << shift
		data = data[n:]
		lane++
	}

	full := len(data) >> 3
	if full > 0 {
		_ = data[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		s.a[lane+i] ^= binary.LittleEndian.Uint64(data[base : base+8])
	}
	if rem := len(data) & 7; rem > 0 {
		base := full << 3
		s.a[lane+full] ^= loadPartialLE(data[base : base+rem])
	}
}

// ExtractCV extracts a 32-byte chain value (lanes 0-3) from instance inst of a State2.
func (s *State2) ExtractCV(inst int) [32]byte {
	var cv [32]byte
	binary.LittleEndian.PutUint64(cv[0:8], s.a[0][inst])
	binary.LittleEndian.PutUint64(cv[8:16], s.a[1][inst])
	binary.LittleEndian.PutUint64(cv[16:24], s.a[2][inst])
	binary.LittleEndian.PutUint64(cv[24:32], s.a[3][inst])
	return cv
}

// ExtractCV extracts a 32-byte chain value (lanes 0-3) from instance inst of a State4.
func (s *State4) ExtractCV(inst int) [32]byte {
	var cv [32]byte
	binary.LittleEndian.PutUint64(cv[0:8], s.a[0][inst])
	binary.LittleEndian.PutUint64(cv[8:16], s.a[1][inst])
	binary.LittleEndian.PutUint64(cv[16:24], s.a[2][inst])
	binary.LittleEndian.PutUint64(cv[24:32], s.a[3][inst])
	return cv
}

// ExtractCV extracts a 32-byte chain value (lanes 0-3) from instance inst of a State8.
func (s *State8) ExtractCV(inst int) [32]byte {
	var cv [32]byte
	binary.LittleEndian.PutUint64(cv[0:8], s.a[0][inst])
	binary.LittleEndian.PutUint64(cv[8:16], s.a[1][inst])
	binary.LittleEndian.PutUint64(cv[16:24], s.a[2][inst])
	binary.LittleEndian.PutUint64(cv[24:32], s.a[3][inst])
	return cv
}

// EncryptBytesAt performs overwrite-mode encryption starting at byte position pos:
func (s *State1) EncryptBytesAt(pos int, src, dst []byte) {
	lane := pos >> 3
	off := pos & 7

	if off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		w := loadPartialLE(src[:n]) << shift
		s.a[lane] ^= w
		storePartialLE(dst[:n], s.a[lane]>>shift)
		src = src[n:]
		dst = dst[n:]
		lane++
	}

	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		w := binary.LittleEndian.Uint64(src[base : base+8])
		s.a[lane+i] ^= w
		binary.LittleEndian.PutUint64(dst[base:base+8], s.a[lane+i])
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		w := loadPartialLE(src[base : base+rem])
		s.a[lane+full] ^= w
		storePartialLE(dst[base:base+rem], s.a[lane+full])
	}
}

// DecryptBytesAt performs overwrite-mode decryption starting at byte position pos.
func (s *State1) DecryptBytesAt(pos int, src, dst []byte) {
	lane := pos >> 3
	off := pos & 7

	if off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		mask := (uint64(1)<<(uint(n)*8) - 1) << shift
		ct := loadPartialLE(src[:n]) << shift
		storePartialLE(dst[:n], (ct^(s.a[lane]&mask))>>shift)
		s.a[lane] = (s.a[lane] & ^mask) | ct
		src = src[n:]
		dst = dst[n:]
		lane++
	}

	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1] // BCE hint
		_ = dst[full*8-1] // BCE hint
	}
	for i := range full {
		base := i << 3
		ct := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct^s.a[lane+i])
		s.a[lane+i] = ct
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		ct := loadPartialLE(src[base : base+rem])
		mask := uint64(1)<<(uint(rem)*8) - 1
		storePartialLE(dst[base:base+rem], ct^(s.a[lane+full]&mask))
		s.a[lane+full] = (s.a[lane+full] & ^mask) | ct
	}
}

func (s *State2) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State2) FastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-stride, 0) // last instance starts at in[stride:]
	n = (n / Rate) * Rate
	if n > 0 && fastLoopAbsorb168x2Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		p0 := (*[Rate]byte)(in[off : off+Rate])
		p1 := (*[Rate]byte)(in[stride+off : stride+off+Rate])
		for lane := range Rate >> 3 {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(p0[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(p1[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State2) AbsorbFinal(tail0, tail1 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) >= Rate {
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
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	for inst := range 2 {
		xorByteInWord(&s.a[posLane][inst], pos, ds)
		xorByteInWord(&s.a[endLane][inst], end, 0x80)
	}
}

// FastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes.
// Instance i reads from src[i*stride:], writes to dst[i*stride:]. Returns bytes processed per instance.
func (s *State2) FastLoopEncrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopEncrypt168x2Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 2 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt168 decrypts ciphertext and permutes.
func (s *State2) FastLoopDecrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopDecrypt168x2Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 2 {
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

// PadPermute applies pad10*1 padding (ds at pos, 0x80 at Rate-1) and permutes all instances.
func (s *State2) PadPermute(pos int, ds byte) {
	shift := uint((pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := pos >> 3
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	for inst := range 2 {
		s.a[posLane][inst] ^= dsMask
		s.a[endLane][inst] ^= endMask
	}
	s.Permute12()
}

// EncryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State2) EncryptBytes(inst int, src, dst []byte) {
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

// DecryptBytes performs SpongeWrap decryption on a partial block for instance inst.
func (s *State2) DecryptBytes(inst int, src, dst []byte) {
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

func (s *State4) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State4) FastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-3*stride, 0) // last instance starts at in[3*stride:]
	n = (n / Rate) * Rate
	if n > 0 && fastLoopAbsorb168x4Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		p0 := (*[Rate]byte)(in[off : off+Rate])
		p1 := (*[Rate]byte)(in[stride+off : stride+off+Rate])
		p2 := (*[Rate]byte)(in[2*stride+off : 2*stride+off+Rate])
		p3 := (*[Rate]byte)(in[3*stride+off : 3*stride+off+Rate])
		for lane := range Rate >> 3 {
			base := lane << 3
			s.a[lane][0] ^= binary.LittleEndian.Uint64(p0[base : base+8])
			s.a[lane][1] ^= binary.LittleEndian.Uint64(p1[base : base+8])
			s.a[lane][2] ^= binary.LittleEndian.Uint64(p2[base : base+8])
			s.a[lane][3] ^= binary.LittleEndian.Uint64(p3[base : base+8])
		}
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State4) AbsorbFinal(tail0, tail1, tail2, tail3 []byte, ds byte) {

	if len(tail0) != len(tail1) || len(tail0) != len(tail2) || len(tail0) != len(tail3) || len(tail0) >= Rate {
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
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	for inst := range 4 {
		xorByteInWord(&s.a[posLane][inst], pos, ds)
		xorByteInWord(&s.a[endLane][inst], end, 0x80)
	}
}

// FastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes.
func (s *State4) FastLoopEncrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-3*stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopEncrypt168x4Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 4 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt168 decrypts ciphertext and permutes.
func (s *State4) FastLoopDecrypt168(src, dst []byte, stride int) int {
	n := max(len(src)-3*stride, 0)
	n = (n / Rate) * Rate
	if n > 0 && fastLoopDecrypt168x4Arch(s, src, dst, stride, n) {
		return n
	}
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			for inst := range 4 {
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

// PadPermute applies pad10*1 padding (ds at pos, 0x80 at Rate-1) and permutes all instances.
func (s *State4) PadPermute(pos int, ds byte) {
	shift := uint((pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := pos >> 3
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	for inst := range 4 {
		s.a[posLane][inst] ^= dsMask
		s.a[endLane][inst] ^= endMask
	}
	s.Permute12()
}

// EncryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State4) EncryptBytes(inst int, src, dst []byte) {
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

// DecryptBytes performs SpongeWrap decryption on a partial block for instance inst.
func (s *State4) DecryptBytes(inst int, src, dst []byte) {
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

func (s *State8) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State8) FastLoopAbsorb168(in []byte, stride int) int {
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

// AbsorbFinal absorbs final partial 168-byte blocks and applies Keccak padding.
func (s *State8) AbsorbFinal(tail0, tail1, tail2, tail3, tail4, tail5, tail6, tail7 []byte, ds byte) {

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

// FastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes.
func (s *State8) FastLoopEncrypt168(src, dst []byte, stride int) int {
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

// FastLoopDecrypt168 decrypts ciphertext and permutes.
func (s *State8) FastLoopDecrypt168(src, dst []byte, stride int) int {
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

// PadPermute applies pad10*1 padding (ds at pos, 0x80 at Rate-1) and permutes all instances.
func (s *State8) PadPermute(pos int, ds byte) {
	shift := uint((pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := pos >> 3
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	for inst := range 8 {
		s.a[posLane][inst] ^= dsMask
		s.a[endLane][inst] ^= endMask
	}
	s.Permute12()
}

// EncryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State8) EncryptBytes(inst int, src, dst []byte) {
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

// DecryptBytes performs SpongeWrap decryption on a partial block for instance inst.
func (s *State8) DecryptBytes(inst int, src, dst []byte) {
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
