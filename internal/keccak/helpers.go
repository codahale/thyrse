package keccak

import "encoding/binary"

const (
	Rate    = 168
	Rate167 = 167
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

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes
// for each full 167-byte block. Returns bytes processed (multiple of 167).
func (s *State1) FastLoopEncrypt167(src, dst []byte, paddingByte byte) int {
	n := (len(src) / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x1Arch(s, src[:n], dst[:n], padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			w := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			s.a[lane] ^= w
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], s.a[lane])
		}
		w := loadPartialLE(src[off+160 : off+167])
		s.a[20] ^= w
		storePartialLE(dst[off+160:off+167], s.a[20])
		s.a[20] ^= padWord
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt167 decrypts ciphertext (plaintext = ct ^ state, state = ct), pads, and permutes
// for each full 167-byte block. Returns bytes processed (multiple of 167).
func (s *State1) FastLoopDecrypt167(src, dst []byte, paddingByte byte) int {
	n := (len(src) / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x1Arch(s, src[:n], dst[:n], padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			ct := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			pt := ct ^ s.a[lane]
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], pt)
			s.a[lane] = ct
		}
		ct := loadPartialLE(src[off+160 : off+167])
		pt := ct ^ (s.a[20] & 0x00ffffffffffffff)
		storePartialLE(dst[off+160:off+167], pt)
		s.a[20] = (s.a[20] & 0xff00000000000000) | ct
		s.a[20] ^= padWord
		s.Permute12()
	}
	return n
}

// XORByteAt XORs byte b into the state at byte position pos.
func (s *State1) XORByteAt(pos int, b byte) {
	xorByteInWord(&s.a[pos>>3], pos, b)
}

// PadPermute applies TurboSHAKE padding (ds at pos, 0x80 at Rate-1) and permutes.
func (s *State1) PadPermute(pos int, ds byte) {
	xorByteInWord(&s.a[pos>>3], pos, ds)
	xorByteInWord(&s.a[(Rate-1)>>3], Rate-1, 0x80)
	s.Permute12()
}

// ExtractBytes copies the first len(dst) bytes from the state.
func (s *State1) ExtractBytes(dst []byte) {
	full := len(dst) >> 3
	for i := range full {
		binary.LittleEndian.PutUint64(dst[i*8:i*8+8], s.a[i])
	}
	if rem := len(dst) & 7; rem > 0 {
		storePartialLE(dst[full*8:], s.a[full])
	}
}

// EncryptBytes performs overwrite-mode encryption starting at byte 0:
// dst[i] = src[i] ^ state[i], state[i] = dst[i].
func (s *State1) EncryptBytes(src, dst []byte) {
	full := len(src) >> 3
	for i := range full {
		base := i << 3
		w := binary.LittleEndian.Uint64(src[base : base+8])
		s.a[i] ^= w
		binary.LittleEndian.PutUint64(dst[base:base+8], s.a[i])
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		w := loadPartialLE(src[base : base+rem])
		s.a[full] ^= w
		storePartialLE(dst[base:base+rem], s.a[full])
	}
}

// EncryptBytesAt performs overwrite-mode encryption starting at byte position pos.
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

// DecryptBytes performs overwrite-mode decryption starting at byte 0:
// dst[i] = src[i] ^ state[i], state[i] = src[i].
func (s *State1) DecryptBytes(src, dst []byte) {
	full := len(src) >> 3
	for i := range full {
		base := i << 3
		ct := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct^s.a[i])
		s.a[i] = ct
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		ct := loadPartialLE(src[base : base+rem])
		mask := uint64(1)<<(rem*8) - 1
		storePartialLE(dst[base:base+rem], ct^(s.a[full]&mask))
		s.a[full] = (s.a[full] & ^mask) | ct
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
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes.
// Instance i reads from src[i*stride:], writes to dst[i*stride:]. Returns bytes processed per instance.
func (s *State2) FastLoopEncrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x2Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 2 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		for inst := range 2 {
			w := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			s.a[20][inst] ^= w
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], s.a[20][inst])
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt167 decrypts ciphertext, pads, and permutes.
func (s *State2) FastLoopDecrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x2Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 2 {
				ct := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				pt := ct ^ s.a[lane][inst]
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], pt)
				s.a[lane][inst] = ct
			}
		}
		for inst := range 2 {
			ct := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			pt := ct ^ (s.a[20][inst] & 0x00ffffffffffffff)
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], pt)
			s.a[20][inst] = (s.a[20][inst] & 0xff00000000000000) | ct
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}

// XORByteAt XORs byte b into all instances at byte position pos.
func (s *State2) XORByteAt(pos int, b byte) {
	shift := uint((pos & 7) << 3)
	mask := uint64(b) << shift
	lane := pos >> 3
	s.a[lane][0] ^= mask
	s.a[lane][1] ^= mask
}

// PadPermute applies TurboSHAKE padding (ds at pos, 0x80 at Rate-1) and permutes all instances.
func (s *State2) PadPermute(pos int, ds byte) {
	shift := uint((pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := pos >> 3
	s.a[posLane][0] ^= dsMask
	s.a[posLane][1] ^= dsMask
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	s.a[endLane][0] ^= endMask
	s.a[endLane][1] ^= endMask
	s.Permute12()
}

// ExtractBytes copies the first len(dst) bytes from instance inst.
func (s *State2) ExtractBytes(inst int, dst []byte) {
	full := len(dst) >> 3
	for i := range full {
		binary.LittleEndian.PutUint64(dst[i*8:i*8+8], s.a[i][inst])
	}
	if rem := len(dst) & 7; rem > 0 {
		storePartialLE(dst[full*8:], s.a[full][inst])
	}
}

// EncryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State2) EncryptBytes(inst int, src, dst []byte) {
	full := len(src) >> 3
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
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	xorByteInWord(&s.a[posLane][2], pos, ds)
	xorByteInWord(&s.a[posLane][3], pos, ds)
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
	xorByteInWord(&s.a[endLane][2], end, 0x80)
	xorByteInWord(&s.a[endLane][3], end, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes.
func (s *State4) FastLoopEncrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-3*stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x4Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 4 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		for inst := range 4 {
			w := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			s.a[20][inst] ^= w
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], s.a[20][inst])
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt167 decrypts ciphertext, pads, and permutes.
func (s *State4) FastLoopDecrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-3*stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x4Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 4 {
				ct := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				pt := ct ^ s.a[lane][inst]
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], pt)
				s.a[lane][inst] = ct
			}
		}
		for inst := range 4 {
			ct := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			pt := ct ^ (s.a[20][inst] & 0x00ffffffffffffff)
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], pt)
			s.a[20][inst] = (s.a[20][inst] & 0xff00000000000000) | ct
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}

// XORByteAt XORs byte b into all instances at byte position pos.
func (s *State4) XORByteAt(pos int, b byte) {
	shift := uint((pos & 7) << 3)
	mask := uint64(b) << shift
	lane := pos >> 3
	s.a[lane][0] ^= mask
	s.a[lane][1] ^= mask
	s.a[lane][2] ^= mask
	s.a[lane][3] ^= mask
}

// PadPermute applies TurboSHAKE padding (ds at pos, 0x80 at Rate-1) and permutes all instances.
func (s *State4) PadPermute(pos int, ds byte) {
	shift := uint((pos & 7) << 3)
	dsMask := uint64(ds) << shift
	posLane := pos >> 3
	s.a[posLane][0] ^= dsMask
	s.a[posLane][1] ^= dsMask
	s.a[posLane][2] ^= dsMask
	s.a[posLane][3] ^= dsMask
	endShift := uint(((Rate - 1) & 7) << 3)
	endMask := uint64(0x80) << endShift
	endLane := (Rate - 1) >> 3
	s.a[endLane][0] ^= endMask
	s.a[endLane][1] ^= endMask
	s.a[endLane][2] ^= endMask
	s.a[endLane][3] ^= endMask
	s.Permute12()
}

// ExtractBytes copies the first len(dst) bytes from instance inst.
func (s *State4) ExtractBytes(inst int, dst []byte) {
	full := len(dst) >> 3
	for i := range full {
		binary.LittleEndian.PutUint64(dst[i*8:i*8+8], s.a[i][inst])
	}
	if rem := len(dst) & 7; rem > 0 {
		storePartialLE(dst[full*8:], s.a[full][inst])
	}
}

// EncryptBytes performs SpongeWrap encryption on a partial block for instance inst.
func (s *State4) EncryptBytes(inst int, src, dst []byte) {
	full := len(src) >> 3
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
	xorByteInWord(&s.a[posLane][0], pos, ds)
	xorByteInWord(&s.a[posLane][1], pos, ds)
	xorByteInWord(&s.a[posLane][2], pos, ds)
	xorByteInWord(&s.a[posLane][3], pos, ds)
	xorByteInWord(&s.a[posLane][4], pos, ds)
	xorByteInWord(&s.a[posLane][5], pos, ds)
	xorByteInWord(&s.a[posLane][6], pos, ds)
	xorByteInWord(&s.a[posLane][7], pos, ds)
	endLane := (Rate - 1) >> 3
	end := Rate - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
	xorByteInWord(&s.a[endLane][2], end, 0x80)
	xorByteInWord(&s.a[endLane][3], end, 0x80)
	xorByteInWord(&s.a[endLane][4], end, 0x80)
	xorByteInWord(&s.a[endLane][5], end, 0x80)
	xorByteInWord(&s.a[endLane][6], end, 0x80)
	xorByteInWord(&s.a[endLane][7], end, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes.
func (s *State8) FastLoopEncrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x8Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 8 {
				w := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				s.a[lane][inst] ^= w
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], s.a[lane][inst])
			}
		}
		for inst := range 8 {
			w := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			s.a[20][inst] ^= w
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], s.a[20][inst])
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}

// FastLoopDecrypt167 decrypts ciphertext, pads, and permutes.
func (s *State8) FastLoopDecrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-7*stride, 0)
	n = (n / Rate167) * Rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x8Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			for inst := range 8 {
				ct := binary.LittleEndian.Uint64(src[inst*stride+off+base : inst*stride+off+base+8])
				pt := ct ^ s.a[lane][inst]
				binary.LittleEndian.PutUint64(dst[inst*stride+off+base:inst*stride+off+base+8], pt)
				s.a[lane][inst] = ct
			}
		}
		for inst := range 8 {
			ct := loadPartialLE(src[inst*stride+off+160 : inst*stride+off+167])
			pt := ct ^ (s.a[20][inst] & 0x00ffffffffffffff)
			storePartialLE(dst[inst*stride+off+160:inst*stride+off+167], pt)
			s.a[20][inst] = (s.a[20][inst] & 0xff00000000000000) | ct
			s.a[20][inst] ^= padWord
		}
		s.Permute12()
	}
	return n
}
