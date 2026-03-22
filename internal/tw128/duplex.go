package tw128

import "encoding/binary"

// duplex is the TW128-owned x1 keyed/body transcript state.
type duplex struct {
	a   [lanes]uint64
	pos int
}

func permute12x1Generic(d *duplex) {
	keccakP1600x12(&d.a)
}

func (d *duplex) permute12() {
	if permute12x1Arch(d) {
		return
	}
	permute12x1Generic(d)
}

func (d *duplex) initKeyed(key, iv []byte) {
	_ = key[31]
	_ = iv[rate-1]
	for lane := range 4 {
		d.a[lane] = binary.LittleEndian.Uint64(key[lane<<3 : lane<<3+8])
	}
	for lane := range rate >> 3 {
		d.a[4+lane] = binary.LittleEndian.Uint64(iv[lane<<3 : lane<<3+8])
	}
	d.permute12()
	d.pos = 0
}

func (d *duplex) absorb(data []byte) {
	if rem := d.pos & 7; rem != 0 {
		need := 8 - rem
		if len(data) < need {
			d.a[d.pos>>3] ^= loadPartialLE(data) << (rem * 8)
			d.pos += len(data)
			return
		}
		var tmp [8]byte
		copy(tmp[rem:], data[:need])
		d.a[d.pos>>3] ^= binary.LittleEndian.Uint64(tmp[:])
		d.pos += need
		data = data[need:]
		if d.pos == rate {
			d.permute12()
			d.pos = 0
		}
	}

	for len(data) >= 8 && d.pos+8 <= rate {
		d.a[d.pos>>3] ^= binary.LittleEndian.Uint64(data[:8])
		d.pos += 8
		data = data[8:]
		if d.pos == rate {
			d.permute12()
			d.pos = 0
		}
	}

	if len(data) > 0 {
		d.a[d.pos>>3] ^= loadPartialLE(data)
		d.pos += len(data)
	}
}

func (d *duplex) absorbCV(src *duplex) {
	d.absorbCVlanes(src.a[0], src.a[1], src.a[2], src.a[3])
}

func (d *duplex) absorbCVs(cvs []byte) {
	for len(cvs) >= 32 {
		d.absorbCVlanes(
			binary.LittleEndian.Uint64(cvs[0:]),
			binary.LittleEndian.Uint64(cvs[8:]),
			binary.LittleEndian.Uint64(cvs[16:]),
			binary.LittleEndian.Uint64(cvs[24:]),
		)
		cvs = cvs[32:]
	}
}

func (d *duplex) absorbCVlanes(w0, w1, w2, w3 uint64) {
	lane := d.pos >> 3
	remaining := (rate >> 3) - lane
	if remaining >= 4 {
		d.a[lane] ^= w0
		d.a[lane+1] ^= w1
		d.a[lane+2] ^= w2
		d.a[lane+3] ^= w3
		d.pos += 32
		if d.pos == rate {
			d.permute12()
			d.pos = 0
		}
		return
	}

	words := [4]uint64{w0, w1, w2, w3}
	for i := range remaining {
		d.a[lane+i] ^= words[i]
	}
	d.permute12()
	d.pos = 0
	for i := remaining; i < 4; i++ {
		d.a[i-remaining] ^= words[i]
		d.pos += 8
	}
}

func (d *duplex) encryptBytesAt(pos int, src, dst []byte) {
	lane := pos >> 3
	off := pos & 7

	if off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		w := loadPartialLE(src[:n]) << shift
		d.a[lane] ^= w
		storePartialLE(dst[:n], d.a[lane]>>shift)
		src = src[n:]
		dst = dst[n:]
		lane++
	}

	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1]
		_ = dst[full*8-1]
	}
	for i := range full {
		base := i << 3
		w := binary.LittleEndian.Uint64(src[base : base+8])
		d.a[lane+i] ^= w
		binary.LittleEndian.PutUint64(dst[base:base+8], d.a[lane+i])
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		w := loadPartialLE(src[base : base+rem])
		d.a[lane+full] ^= w
		storePartialLE(dst[base:base+rem], d.a[lane+full])
	}
}

func (d *duplex) decryptBytesAt(pos int, src, dst []byte) {
	lane := pos >> 3
	off := pos & 7

	if off != 0 {
		n := min(8-off, len(src))
		shift := uint(off) << 3
		mask := (uint64(1)<<(uint(n)*8) - 1) << shift
		ct := loadPartialLE(src[:n]) << shift
		storePartialLE(dst[:n], (ct^(d.a[lane]&mask))>>shift)
		d.a[lane] = (d.a[lane] & ^mask) | ct
		src = src[n:]
		dst = dst[n:]
		lane++
	}

	full := len(src) >> 3
	if full > 0 {
		_ = src[full*8-1]
		_ = dst[full*8-1]
	}
	for i := range full {
		base := i << 3
		ct := binary.LittleEndian.Uint64(src[base : base+8])
		binary.LittleEndian.PutUint64(dst[base:base+8], ct^d.a[lane+i])
		d.a[lane+i] = ct
	}
	if rem := len(src) & 7; rem > 0 {
		base := full << 3
		ct := loadPartialLE(src[base : base+rem])
		mask := uint64(1)<<(uint(rem)*8) - 1
		storePartialLE(dst[base:base+rem], ct^(d.a[lane+full]&mask))
		d.a[lane+full] = (d.a[lane+full] & ^mask) | ct
	}
}

func (d *duplex) bodyEncryptLoop(src, dst []byte) int {
	n := (len(src) / rate) * rate
	for off := 0; off < n; off += rate {
		for lane := range rate >> 3 {
			base := lane << 3
			w := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			d.a[lane] ^= w
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], d.a[lane])
		}
		d.a[21] ^= 0x01
		d.permute12()
	}
	return n
}

func (d *duplex) bodyDecryptLoop(src, dst []byte) int {
	n := (len(src) / rate) * rate
	for off := 0; off < n; off += rate {
		for lane := range rate >> 3 {
			base := lane << 3
			ct := binary.LittleEndian.Uint64(src[off+base : off+base+8])
			pt := ct ^ d.a[lane]
			binary.LittleEndian.PutUint64(dst[off+base:off+base+8], pt)
			d.a[lane] = ct
		}
		d.a[21] ^= 0x01
		d.permute12()
	}
	return n
}

func (d *duplex) bodyXOR(dst, src []byte, decrypt bool) {
	if d.pos > 0 && len(src) > 0 {
		n := min(rate-d.pos, len(src))
		if decrypt {
			d.decryptBytesAt(d.pos, src[:n], dst[:n])
		} else {
			d.encryptBytesAt(d.pos, src[:n], dst[:n])
		}
		d.pos += n
		src = src[n:]
		dst = dst[n:]
		if d.pos == rate {
			d.a[21] ^= 0x01
			d.permute12()
			d.pos = 0
		}
	}

	if d.pos == 0 && len(src) >= rate {
		var done int
		if decrypt {
			done = d.bodyDecryptLoop(src, dst)
		} else {
			done = d.bodyEncryptLoop(src, dst)
		}
		src = src[done:]
		dst = dst[done:]
	}

	if len(src) > 0 {
		if decrypt {
			d.decryptBytesAt(d.pos, src, dst)
		} else {
			d.encryptBytesAt(d.pos, src, dst)
		}
		d.pos += len(src)
	}
}

func (d *duplex) setPos(pos int) {
	d.pos = pos
}

func (d *duplex) padStarPermute() {
	xorByteInWord(&d.a[d.pos>>3], d.pos, 0x01)
	d.permute12()
	d.pos = 0
}

func (d *duplex) bodyPadStarPermute() {
	xorByteInWord(&d.a[d.pos>>3], d.pos, 0x01)
	d.a[21] ^= 0x01
	d.permute12()
	d.pos = 0
}

func (d *duplex) squeeze(dst []byte) {
	for len(dst) > 0 {
		if d.pos == rate {
			d.permute12()
			d.pos = 0
		}
		lane := d.pos >> 3
		off := d.pos & 7
		if off != 0 {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], d.a[lane])
			n := copy(dst, tmp[off:])
			d.pos += n
			dst = dst[n:]
			continue
		}
		for len(dst) >= 8 && d.pos+8 <= rate {
			binary.LittleEndian.PutUint64(dst[:8], d.a[d.pos>>3])
			d.pos += 8
			dst = dst[8:]
		}
		if len(dst) > 0 && d.pos < rate {
			var tmp [8]byte
			binary.LittleEndian.PutUint64(tmp[:], d.a[d.pos>>3])
			n := copy(dst, tmp[:])
			d.pos += n
			dst = dst[n:]
		}
	}
}
