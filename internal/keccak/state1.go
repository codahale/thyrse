package keccak

import "encoding/binary"

// State1 is a single lane-major Keccak-p[1600] state with duplex position tracking.
type State1 struct {
	a   [lanes]uint64
	pos int
}

func permute12x1Generic(s *State1) {
	keccakP1600x12(&s.a)
}

func (s *State1) permute12() {
	if permute12x1Arch(s) {
		return
	}
	permute12x1Generic(s)
}

func (s *State1) Reset() {
	clear(s.a[:])
	s.pos = 0
}

// fastLoopAbsorb168 absorbs and permutes as many full 168-byte stripes as possible.
func (s *State1) fastLoopAbsorb168(in []byte) int {
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
		s.permute12()
	}
	return n
}

// absorbFinal absorbs a final partial 168-byte block and applies Keccak padding.
func (s *State1) absorbFinal(tail []byte, ds byte) {

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

// fastLoopEncrypt168 XORs plaintext into state, outputs ciphertext, and permutes
// for each full 168-byte block. Returns bytes processed (multiple of 168).
func (s *State1) fastLoopEncrypt168(src, dst []byte) int {
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
		s.permute12()
	}
	return n
}

// fastLoopDecrypt168 decrypts ciphertext (plaintext = ct ^ state, state = ct), and permutes
// for each full 168-byte block. Returns bytes processed (multiple of 168).
func (s *State1) fastLoopDecrypt168(src, dst []byte) int {
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
		s.permute12()
	}
	return n
}

// padPermute applies pad10*1 padding (ds at pos, 0x80 at Rate-1) and permutes.
func (s *State1) padPermute(pos int, ds byte) {
	xorByteInWord(&s.a[pos>>3], pos, ds)
	xorByteInWord(&s.a[(Rate-1)>>3], Rate-1, 0x80)
	s.permute12()
}

// encryptBytesAt performs overwrite-mode encryption starting at byte position pos:
func (s *State1) encryptBytesAt(pos int, src, dst []byte) {
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

// decryptBytesAt performs overwrite-mode decryption starting at byte position pos.
func (s *State1) decryptBytesAt(pos int, src, dst []byte) {
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

// AbsorbAll absorbs all data, applies padding with ds, and permutes.
func (s *State1) AbsorbAll(in []byte, ds byte) {
	done := s.fastLoopAbsorb168(in)
	s.absorbFinal(in[done:], ds)
	s.permute12()
	s.pos = 0
}

// Absorb XOR-absorbs data into the sponge state, permuting at rate boundaries.
func (s *State1) Absorb(data []byte) {
	// If we have a partial lane buffered, fill it first.
	if rem := s.pos & 7; rem != 0 {
		need := 8 - rem
		if len(data) < need {
			s.a[s.pos>>3] ^= loadPartialLE(data) << (rem * 8)
			s.pos += len(data)
			return
		}
		// Complete the partial lane.
		var tmp [8]byte
		copy(tmp[rem:], data[:need])
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		s.pos += need
		data = data[need:]
		if s.pos == Rate {
			s.permute12()
			s.pos = 0
		}
	}

	// Absorb full stripes directly via FastLoopAbsorb168.
	if s.pos == 0 && len(data) >= Rate {
		absorbed := s.fastLoopAbsorb168(data)
		data = data[absorbed:]
	}

	// Absorb remaining full lanes.
	for len(data) >= 8 && s.pos+8 <= Rate {
		s.a[s.pos>>3] ^= binary.LittleEndian.Uint64(data[:8])
		s.pos += 8
		data = data[8:]
		if s.pos == Rate {
			s.permute12()
			s.pos = 0
		}
	}

	// Buffer any remaining partial lane.
	if len(data) > 0 {
		s.a[s.pos>>3] ^= loadPartialLE(data)
		s.pos += len(data)
	}
}

// AbsorbCV absorbs a 32-byte chain value from src by reading its first 4 lanes.
// The position must be lane-aligned (multiple of 8).
func (s *State1) AbsorbCV(src *State1) {
	if s.pos&7 != 0 {
		panic("keccak: AbsorbCV on non-lane-aligned state")
	}
	s.absorbCVlanes(src.a[0], src.a[1], src.a[2], src.a[3])
}

// AbsorbCVs absorbs n 32-byte chain values from a contiguous byte buffer.
// The position must be lane-aligned (multiple of 8). Each CV is 4 LE uint64 lanes.
func (s *State1) AbsorbCVs(cvs []byte) {
	if s.pos&7 != 0 {
		panic("keccak: AbsorbCVs on non-lane-aligned state")
	}
	for len(cvs) >= 32 {
		w0 := binary.LittleEndian.Uint64(cvs[0:])
		w1 := binary.LittleEndian.Uint64(cvs[8:])
		w2 := binary.LittleEndian.Uint64(cvs[16:])
		w3 := binary.LittleEndian.Uint64(cvs[24:])
		s.absorbCVlanes(w0, w1, w2, w3)
		cvs = cvs[32:]
	}
}

// absorbCVlanes absorbs a 4-lane (32-byte) chain value. The caller must ensure
// s.pos is lane-aligned.
func (s *State1) absorbCVlanes(w0, w1, w2, w3 uint64) {
	lane := s.pos >> 3
	remaining := (Rate >> 3) - lane
	if remaining >= 4 {
		s.a[lane] ^= w0
		s.a[lane+1] ^= w1
		s.a[lane+2] ^= w2
		s.a[lane+3] ^= w3
		s.pos += 32
		if s.pos == Rate {
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

// encrypt XOR-encrypts plaintext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (s *State1) encrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.encryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.permute12()
			s.pos = 0
		}
	}

	// Encrypt full blocks via FastLoopEncrypt168.
	if s.pos == 0 && len(src) >= Rate {
		done := s.fastLoopEncrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Encrypt remaining partial block.
	if len(src) > 0 {
		s.encryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// decrypt XOR-decrypts ciphertext from src into dst, permuting at rate
// boundaries. The caller must ensure len(dst) >= len(src).
func (s *State1) decrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.decryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.permute12()
			s.pos = 0
		}
	}

	// Decrypt full blocks via FastLoopDecrypt168.
	if s.pos == 0 && len(src) >= Rate {
		done := s.fastLoopDecrypt168(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Decrypt remaining partial block.
	if len(src) > 0 {
		s.decryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// PadPermute applies pad10*1 padding at the current position with domain
// separation byte ds, then permutes. Resets pos to 0.
func (s *State1) PadPermute(ds byte) {
	s.padPermute(s.pos, ds)
	s.pos = 0
}

// PadPermute2 applies pad10*1 padding with ds to both a and b (which may have
// different states but must be at the same position), permutes both, and
// leaves both at pos=0 ready to squeeze.
func (a *State1) PadPermute2(b *State1, ds byte) {
	if a.pos != b.pos {
		panic("keccak: PadPermute2 with mismatched positions")
	}
	padPermute2(a, b, ds)
	a.pos = 0
	b.pos = 0
}

// Equal returns 1 if s and other represent identical states, 0 otherwise.
// The comparison is constant-time with respect to the keccak state.
func (s *State1) Equal(other *State1) int {
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
	posEq := int(1 - (posAcc & 1))

	return lanesEq & posEq
}

// InitKeyed sets the state to key || iv (Mennink keyed duplex init), then
// permutes. Key must be 32 bytes (4 lanes) and iv must be 168 bytes (21 lanes),
// filling the full 200-byte state. Resets pos to 0.
func (s *State1) InitKeyed(key, iv []byte) {
	_ = key[31] // bounds check
	_ = iv[167] // bounds check
	for lane := range 4 {
		s.a[lane] = binary.LittleEndian.Uint64(key[lane<<3 : lane<<3+8])
	}
	for lane := range 21 {
		s.a[4+lane] = binary.LittleEndian.Uint64(iv[lane<<3 : lane<<3+8])
	}
	s.permute12()
	s.pos = 0
}

// PadStarPermute applies pad10* padding at the current position and permutes.
// Unlike PadPermute (pad10*1), only a single 0x01 byte is XORed at pos — there
// is no trailing 0x80 at Rate-1. Resets pos to 0.
func (s *State1) PadStarPermute() {
	xorByteInWord(&s.a[s.pos>>3], s.pos, 0x01)
	s.permute12()
	s.pos = 0
}

// SetPos sets the internal position counter.
func (s *State1) SetPos(pos int) { s.pos = pos }

// EncryptBytesAt performs XOR encryption starting at byte position pos.
func (s *State1) EncryptBytesAt(pos int, src, dst []byte) { s.encryptBytesAt(pos, src, dst) }

// DecryptBytesAt performs overwrite-mode decryption starting at byte position pos.
func (s *State1) DecryptBytesAt(pos int, src, dst []byte) { s.decryptBytesAt(pos, src, dst) }

// BodyEncryptLoop encrypts full 168-byte body blocks with capacity framing.
// XORs 0x01 into lane 21 before each permute. Returns bytes processed.
func (s *State1) BodyEncryptLoop(src, dst []byte) int {
	n := (len(src) / Rate) * Rate
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			w := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			s.a[lane] ^= w
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], s.a[lane])
		}
		s.a[21] ^= 0x01
		s.permute12()
	}
	return n
}

// BodyDecryptLoop decrypts full 168-byte body blocks with capacity framing.
// XORs 0x01 into lane 21 before each permute. Returns bytes processed.
func (s *State1) BodyDecryptLoop(src, dst []byte) int {
	n := (len(src) / Rate) * Rate
	for off := 0; off < n; off += Rate {
		for lane := range 21 {
			base := lane << 3
			ct := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			pt := ct ^ s.a[lane]
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], pt)
			s.a[lane] = ct
		}
		s.a[21] ^= 0x01
		s.permute12()
	}
	return n
}

// BodyEncrypt XOR-encrypts plaintext with capacity framing (body blocks have
// a 0x01 byte in the first capacity position before each permute). The caller
// must ensure len(dst) >= len(src).
func (s *State1) BodyEncrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.encryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.a[21] ^= 0x01
			s.permute12()
			s.pos = 0
		}
	}

	// Encrypt full blocks with capacity framing.
	if s.pos == 0 && len(src) >= Rate {
		done := s.BodyEncryptLoop(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Encrypt remaining partial block.
	if len(src) > 0 {
		s.encryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// BodyDecrypt XOR-decrypts ciphertext with capacity framing. The caller must
// ensure len(dst) >= len(src).
func (s *State1) BodyDecrypt(dst, src []byte) {
	// Finish any partial block at current position.
	if s.pos > 0 && len(src) > 0 {
		n := min(Rate-s.pos, len(src))
		s.decryptBytesAt(s.pos, src[:n], dst[:n])
		s.pos += n
		src = src[n:]
		dst = dst[n:]
		if s.pos == Rate {
			s.a[21] ^= 0x01
			s.permute12()
			s.pos = 0
		}
	}

	// Decrypt full blocks with capacity framing.
	if s.pos == 0 && len(src) >= Rate {
		done := s.BodyDecryptLoop(src, dst)
		src = src[done:]
		dst = dst[done:]
	}

	// Decrypt remaining partial block.
	if len(src) > 0 {
		s.decryptBytesAt(s.pos, src, dst)
		s.pos += len(src)
	}
}

// BodyPadStarPermute applies pad10* and capacity framing to finalize a body
// phase: XOR 0x01 at current pos (pad10*), XOR 0x01 into lane 21 (capacity),
// permute, reset pos.
func (s *State1) BodyPadStarPermute() {
	xorByteInWord(&s.a[s.pos>>3], s.pos, 0x01)
	s.a[21] ^= 0x01
	s.permute12()
	s.pos = 0
}

// Squeeze extracts bytes from the sponge state into dst, permuting at rate
// boundaries for multi-block output.
func (s *State1) Squeeze(dst []byte) {
	for len(dst) > 0 {
		if s.pos == Rate {
			s.permute12()
			s.pos = 0
		}
		// Squeeze from the current lane.
		lane := s.pos >> 3
		off := s.pos & 7
		if off != 0 {
			// Partial lane: extract remaining bytes from current lane.
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[lane])
			w := copy(dst, tmp[off:])
			s.pos += w
			dst = dst[w:]
			continue
		}
		// Full lanes.
		for len(dst) >= 8 && s.pos+8 <= Rate {
			binary.LittleEndian.PutUint64(dst[:8], s.a[s.pos>>3])
			s.pos += 8
			dst = dst[8:]
		}
		// Partial final lane.
		if len(dst) > 0 && s.pos < Rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], s.a[s.pos>>3])
			w := copy(dst, tmp[:])
			s.pos += w
			dst = dst[w:]
		}
	}
}
