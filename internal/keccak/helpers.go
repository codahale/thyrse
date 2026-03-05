package keccak

import "encoding/binary"

const (
	rate    = 168
	rate167 = 167
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
		s.Permute12()
	}
	return n
}

// AbsorbFinal absorbs a final partial 168-byte block and applies Keccak padding.
func (s *State1) AbsorbFinal(tail []byte, ds byte) {

	if len(tail) >= rate {
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
	xorByteInWord(&s.a[(rate-1)>>3], rate-1, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes
// for each full 167-byte block. Returns bytes processed (multiple of 167).
func (s *State1) FastLoopEncrypt167(src, dst []byte, paddingByte byte) int {
	n := (len(src) / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x1Arch(s, src[:n], dst[:n], padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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
	n := (len(src) / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x1Arch(s, src[:n], dst[:n], padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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

func (s *State2) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State2) FastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-stride, 0) // last instance starts at in[stride:]
	n = (n / rate) * rate
	if n > 0 && fastLoopAbsorb168x2Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += rate {
		p0 := (*[rate]byte)(in[off : off+rate])
		p1 := (*[rate]byte)(in[stride+off : stride+off+rate])
		for lane := range rate >> 3 {
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

	if len(tail0) != len(tail1) || len(tail0) >= rate {
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
	endLane := (rate - 1) >> 3
	end := rate - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes.
// Instance i reads from src[i*stride:], writes to dst[i*stride:]. Returns bytes processed per instance.
func (s *State2) FastLoopEncrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-stride, 0)
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x2Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x2Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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

func (s *State4) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State4) FastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-3*stride, 0) // last instance starts at in[3*stride:]
	n = (n / rate) * rate
	if n > 0 && fastLoopAbsorb168x4Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += rate {
		p0 := (*[rate]byte)(in[off : off+rate])
		p1 := (*[rate]byte)(in[stride+off : stride+off+rate])
		p2 := (*[rate]byte)(in[2*stride+off : 2*stride+off+rate])
		p3 := (*[rate]byte)(in[3*stride+off : 3*stride+off+rate])
		for lane := range rate >> 3 {
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

	if len(tail0) != len(tail1) || len(tail0) != len(tail2) || len(tail0) != len(tail3) || len(tail0) >= rate {
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
	endLane := (rate - 1) >> 3
	end := rate - 1
	xorByteInWord(&s.a[endLane][0], end, 0x80)
	xorByteInWord(&s.a[endLane][1], end, 0x80)
	xorByteInWord(&s.a[endLane][2], end, 0x80)
	xorByteInWord(&s.a[endLane][3], end, 0x80)
}

// FastLoopEncrypt167 XORs plaintext into state, outputs ciphertext, pads, and permutes.
func (s *State4) FastLoopEncrypt167(src, dst []byte, stride int, paddingByte byte) int {
	n := max(len(src)-3*stride, 0)
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x4Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x4Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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

func (s *State8) Reset() { clear(s.a[:]) }

// FastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
// Instance i reads from in[i*stride:]. Returns bytes absorbed per instance.
func (s *State8) FastLoopAbsorb168(in []byte, stride int) int {
	n := max(len(in)-7*stride, 0) // last instance starts at in[7*stride:]
	n = (n / rate) * rate
	if n > 0 && fastLoopAbsorb168x8Arch(s, in, stride, n) {
		return n
	}
	for off := 0; off < n; off += rate {
		p0 := (*[rate]byte)(in[off : off+rate])
		p1 := (*[rate]byte)(in[stride+off : stride+off+rate])
		p2 := (*[rate]byte)(in[2*stride+off : 2*stride+off+rate])
		p3 := (*[rate]byte)(in[3*stride+off : 3*stride+off+rate])
		p4 := (*[rate]byte)(in[4*stride+off : 4*stride+off+rate])
		p5 := (*[rate]byte)(in[5*stride+off : 5*stride+off+rate])
		p6 := (*[rate]byte)(in[6*stride+off : 6*stride+off+rate])
		p7 := (*[rate]byte)(in[7*stride+off : 7*stride+off+rate])
		for lane := range rate >> 3 {
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
		len(tail0) != len(tail7) || len(tail0) >= rate {
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
	endLane := (rate - 1) >> 3
	end := rate - 1
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
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopEncrypt167x8Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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
	n = (n / rate167) * rate167
	padWord := uint64(paddingByte) << 56
	if n > 0 && fastLoopDecrypt167x8Arch(s, src, dst, stride, n, padWord) {
		return n
	}
	for off := 0; off < n; off += rate167 {
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
