package keccak

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestFastLoopEncryptDecrypt167 verifies round-trip: encrypt then decrypt
// recovers the original plaintext and produces identical final states.
func TestFastLoopEncryptDecrypt167(t *testing.T) {
	const padByte byte = 0x0B
	const nBlocks = 5
	const blockSize = Rate167

	t.Run("x1", func(t *testing.T) {
		n := nBlocks * blockSize
		pt := make([]byte, n)
		rand.Read(pt)
		ct := make([]byte, n)
		recovered := make([]byte, n)

		var sEnc, sDec State1
		// Seed states identically with some data.
		seed := make([]byte, 200)
		rand.Read(seed)
		for i := range 25 {
			v := uint64(seed[i*8]) | uint64(seed[i*8+1])<<8 | uint64(seed[i*8+2])<<16 | uint64(seed[i*8+3])<<24 |
				uint64(seed[i*8+4])<<32 | uint64(seed[i*8+5])<<40 | uint64(seed[i*8+6])<<48 | uint64(seed[i*8+7])<<56
			sEnc.a[i] = v
			sDec.a[i] = v
		}

		got := sEnc.FastLoopEncrypt167(pt, ct, padByte)
		if got != n {
			t.Fatalf("encrypt returned %d, want %d", got, n)
		}
		got = sDec.FastLoopDecrypt167(ct, recovered, padByte)
		if got != n {
			t.Fatalf("decrypt returned %d, want %d", got, n)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatal("round-trip failed: plaintext != recovered")
		}
		// States should match.
		if sEnc.a != sDec.a {
			t.Fatal("final states differ after encrypt/decrypt")
		}
	})

	t.Run("x2", func(t *testing.T) {
		n := nBlocks * blockSize
		stride := n
		pt := make([]byte, 2*stride)
		rand.Read(pt)
		ct := make([]byte, 2*stride)
		recovered := make([]byte, 2*stride)

		var sEnc, sDec State2
		seed := make([]byte, 400)
		rand.Read(seed)
		for i := range 25 {
			for j := range 2 {
				off := (i*2 + j) * 8
				v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
					uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
				sEnc.a[i][j] = v
				sDec.a[i][j] = v
			}
		}

		got := sEnc.FastLoopEncrypt167(pt, ct, stride, padByte)
		if got != n {
			t.Fatalf("encrypt returned %d, want %d", got, n)
		}
		got = sDec.FastLoopDecrypt167(ct, recovered, stride, padByte)
		if got != n {
			t.Fatalf("decrypt returned %d, want %d", got, n)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatal("round-trip failed")
		}
		if sEnc.a != sDec.a {
			t.Fatal("final states differ")
		}
	})

	t.Run("x4", func(t *testing.T) {
		n := nBlocks * blockSize
		stride := n
		pt := make([]byte, 4*stride)
		rand.Read(pt)
		ct := make([]byte, 4*stride)
		recovered := make([]byte, 4*stride)

		var sEnc, sDec State4
		seed := make([]byte, 800)
		rand.Read(seed)
		for i := range 25 {
			for j := range 4 {
				off := (i*4 + j) * 8
				v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
					uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
				sEnc.a[i][j] = v
				sDec.a[i][j] = v
			}
		}

		got := sEnc.FastLoopEncrypt167(pt, ct, stride, padByte)
		if got != n {
			t.Fatalf("encrypt returned %d, want %d", got, n)
		}
		got = sDec.FastLoopDecrypt167(ct, recovered, stride, padByte)
		if got != n {
			t.Fatalf("decrypt returned %d, want %d", got, n)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatal("round-trip failed")
		}
		if sEnc.a != sDec.a {
			t.Fatal("final states differ")
		}
	})

	t.Run("x8", func(t *testing.T) {
		n := nBlocks * blockSize
		stride := n
		pt := make([]byte, 8*stride)
		rand.Read(pt)
		ct := make([]byte, 8*stride)
		recovered := make([]byte, 8*stride)

		var sEnc, sDec State8
		seed := make([]byte, 1600)
		rand.Read(seed)
		for i := range 25 {
			for j := range 8 {
				off := (i*8 + j) * 8
				v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
					uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
				sEnc.a[i][j] = v
				sDec.a[i][j] = v
			}
		}

		got := sEnc.FastLoopEncrypt167(pt, ct, stride, padByte)
		if got != n {
			t.Fatalf("encrypt returned %d, want %d", got, n)
		}
		got = sDec.FastLoopDecrypt167(ct, recovered, stride, padByte)
		if got != n {
			t.Fatalf("decrypt returned %d, want %d", got, n)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatal("round-trip failed")
		}
		if sEnc.a != sDec.a {
			t.Fatal("final states differ")
		}
	})
}

// seedState1 fills a State1 from a seed slice (must be >= 200 bytes).
func seedState1(s *State1, seed []byte) {
	for i := range 25 {
		off := i * 8
		s.a[i] = uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
			uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
	}
}

// genericEncrypt1 runs x1 encrypt using pure Go logic.
func genericEncrypt1(s *State1, pt, ct []byte, padWord uint64) {
	for off := 0; off < len(pt); off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			w := uint64(pt[off+base]) | uint64(pt[off+base+1])<<8 | uint64(pt[off+base+2])<<16 | uint64(pt[off+base+3])<<24 |
				uint64(pt[off+base+4])<<32 | uint64(pt[off+base+5])<<40 | uint64(pt[off+base+6])<<48 | uint64(pt[off+base+7])<<56
			s.a[lane] ^= w
			v := s.a[lane]
			ct[off+base] = byte(v)
			ct[off+base+1] = byte(v >> 8)
			ct[off+base+2] = byte(v >> 16)
			ct[off+base+3] = byte(v >> 24)
			ct[off+base+4] = byte(v >> 32)
			ct[off+base+5] = byte(v >> 40)
			ct[off+base+6] = byte(v >> 48)
			ct[off+base+7] = byte(v >> 56)
		}
		w := loadPartialLE(pt[off+160 : off+167])
		s.a[20] ^= w
		storePartialLE(ct[off+160:off+167], s.a[20])
		s.a[20] ^= padWord
		s.Permute12()
	}
}

// genericDecrypt1 runs x1 decrypt using pure Go logic.
func genericDecrypt1(s *State1, ct, pt []byte, padWord uint64) {
	for off := 0; off < len(ct); off += Rate167 {
		for lane := range 20 {
			base := lane << 3
			w := uint64(ct[off+base]) | uint64(ct[off+base+1])<<8 | uint64(ct[off+base+2])<<16 | uint64(ct[off+base+3])<<24 |
				uint64(ct[off+base+4])<<32 | uint64(ct[off+base+5])<<40 | uint64(ct[off+base+6])<<48 | uint64(ct[off+base+7])<<56
			ptw := w ^ s.a[lane]
			pt[off+base] = byte(ptw)
			pt[off+base+1] = byte(ptw >> 8)
			pt[off+base+2] = byte(ptw >> 16)
			pt[off+base+3] = byte(ptw >> 24)
			pt[off+base+4] = byte(ptw >> 32)
			pt[off+base+5] = byte(ptw >> 40)
			pt[off+base+6] = byte(ptw >> 48)
			pt[off+base+7] = byte(ptw >> 56)
			s.a[lane] = w
		}
		ctw := loadPartialLE(ct[off+160 : off+167])
		ptw := ctw ^ (s.a[20] & 0x00ffffffffffffff)
		storePartialLE(pt[off+160:off+167], ptw)
		s.a[20] = (s.a[20] & 0xff00000000000000) | ctw
		s.a[20] ^= padWord
		s.Permute12()
	}
}

// TestFastLoopEncrypt167CrossValidation verifies the assembly encrypt matches
// the Go generic fallback by running both with identical inputs and comparing outputs.
func TestFastLoopEncrypt167CrossValidation(t *testing.T) {
	const padByte byte = 0x07
	const nBlocks = 3
	const n = nBlocks * Rate167
	padWord := uint64(padByte) << 56

	t.Run("x1", func(t *testing.T) {
		pt := make([]byte, n)
		rand.Read(pt)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen State1
		seedState1(&sGen, seed)
		ctGen := make([]byte, n)
		genericEncrypt1(&sGen, pt, ctGen, padWord)

		var sAsm State1
		seedState1(&sAsm, seed)
		ctAsm := make([]byte, n)
		sAsm.FastLoopEncrypt167(pt, ctAsm, padByte)

		if !bytes.Equal(ctGen, ctAsm) {
			t.Fatal("assembly output differs from generic")
		}
		if sGen.a != sAsm.a {
			t.Fatal("final state differs")
		}
	})

	t.Run("x2", func(t *testing.T) {
		stride := n
		pt := make([]byte, 2*stride)
		rand.Read(pt)
		seed := make([]byte, 200)
		rand.Read(seed)

		// Run x1 generic on each instance independently.
		var sGen0, sGen1 State1
		seedState1(&sGen0, seed)
		seedState1(&sGen1, seed)
		ctGen := make([]byte, 2*stride)
		genericEncrypt1(&sGen0, pt[:stride], ctGen[:stride], padWord)
		genericEncrypt1(&sGen1, pt[stride:], ctGen[stride:], padWord)

		// Run x2 assembly.
		var sAsm State2
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			sAsm.a[i][0] = v
			sAsm.a[i][1] = v
		}
		ctAsm := make([]byte, 2*stride)
		sAsm.FastLoopEncrypt167(pt, ctAsm, stride, padByte)

		if !bytes.Equal(ctGen, ctAsm) {
			for i := range len(ctGen) {
				if ctGen[i] != ctAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ctGen[i], ctAsm[i])
				}
			}
		}
		for i := range 25 {
			if sAsm.a[i][0] != sGen0.a[i] {
				t.Fatalf("state lane %d inst 0: gen=%016x asm=%016x", i, sGen0.a[i], sAsm.a[i][0])
			}
			if sAsm.a[i][1] != sGen1.a[i] {
				t.Fatalf("state lane %d inst 1: gen=%016x asm=%016x", i, sGen1.a[i], sAsm.a[i][1])
			}
		}
	})

	t.Run("x4", func(t *testing.T) {
		stride := n
		pt := make([]byte, 4*stride)
		rand.Read(pt)
		seed := make([]byte, 200)
		rand.Read(seed)

		// Run x1 generic on each instance.
		var sGen [4]State1
		ctGen := make([]byte, 4*stride)
		for inst := range 4 {
			seedState1(&sGen[inst], seed)
			genericEncrypt1(&sGen[inst], pt[inst*stride:(inst+1)*stride], ctGen[inst*stride:(inst+1)*stride], padWord)
		}

		// Run x4 assembly.
		var sAsm State4
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			for j := range 4 {
				sAsm.a[i][j] = v
			}
		}
		ctAsm := make([]byte, 4*stride)
		sAsm.FastLoopEncrypt167(pt, ctAsm, stride, padByte)

		if !bytes.Equal(ctGen, ctAsm) {
			for i := range len(ctGen) {
				if ctGen[i] != ctAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ctGen[i], ctAsm[i])
				}
			}
		}
		for i := range 25 {
			for j := range 4 {
				if sAsm.a[i][j] != sGen[j].a[i] {
					t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], sAsm.a[i][j])
				}
			}
		}
	})

	t.Run("x8", func(t *testing.T) {
		stride := n
		pt := make([]byte, 8*stride)
		rand.Read(pt)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen [8]State1
		ctGen := make([]byte, 8*stride)
		for inst := range 8 {
			seedState1(&sGen[inst], seed)
			genericEncrypt1(&sGen[inst], pt[inst*stride:(inst+1)*stride], ctGen[inst*stride:(inst+1)*stride], padWord)
		}

		var sAsm State8
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			for j := range 8 {
				sAsm.a[i][j] = v
			}
		}
		ctAsm := make([]byte, 8*stride)
		sAsm.FastLoopEncrypt167(pt, ctAsm, stride, padByte)

		if !bytes.Equal(ctGen, ctAsm) {
			for i := range len(ctGen) {
				if ctGen[i] != ctAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ctGen[i], ctAsm[i])
				}
			}
		}
		for i := range 25 {
			for j := range 8 {
				if sAsm.a[i][j] != sGen[j].a[i] {
					t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], sAsm.a[i][j])
				}
			}
		}
	})
}

// TestFastLoopDecrypt167CrossValidation verifies the assembly decrypt matches
// the Go generic fallback.
func TestFastLoopDecrypt167CrossValidation(t *testing.T) {
	const padByte byte = 0x07
	const nBlocks = 3
	const n = nBlocks * Rate167
	padWord := uint64(padByte) << 56

	t.Run("x1", func(t *testing.T) {
		ct := make([]byte, n)
		rand.Read(ct)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen State1
		seedState1(&sGen, seed)
		ptGen := make([]byte, n)
		genericDecrypt1(&sGen, ct, ptGen, padWord)

		var sAsm State1
		seedState1(&sAsm, seed)
		ptAsm := make([]byte, n)
		sAsm.FastLoopDecrypt167(ct, ptAsm, padByte)

		if !bytes.Equal(ptGen, ptAsm) {
			t.Fatal("assembly output differs from generic")
		}
		if sGen.a != sAsm.a {
			t.Fatal("final state differs")
		}
	})

	t.Run("x2", func(t *testing.T) {
		stride := n
		ct := make([]byte, 2*stride)
		rand.Read(ct)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen0, sGen1 State1
		seedState1(&sGen0, seed)
		seedState1(&sGen1, seed)
		ptGen := make([]byte, 2*stride)
		genericDecrypt1(&sGen0, ct[:stride], ptGen[:stride], padWord)
		genericDecrypt1(&sGen1, ct[stride:], ptGen[stride:], padWord)

		var sAsm State2
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			sAsm.a[i][0] = v
			sAsm.a[i][1] = v
		}
		ptAsm := make([]byte, 2*stride)
		sAsm.FastLoopDecrypt167(ct, ptAsm, stride, padByte)

		if !bytes.Equal(ptGen, ptAsm) {
			for i := range len(ptGen) {
				if ptGen[i] != ptAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ptGen[i], ptAsm[i])
				}
			}
		}
		for i := range 25 {
			if sAsm.a[i][0] != sGen0.a[i] {
				t.Fatalf("state lane %d inst 0: gen=%016x asm=%016x", i, sGen0.a[i], sAsm.a[i][0])
			}
			if sAsm.a[i][1] != sGen1.a[i] {
				t.Fatalf("state lane %d inst 1: gen=%016x asm=%016x", i, sGen1.a[i], sAsm.a[i][1])
			}
		}
	})

	t.Run("x4", func(t *testing.T) {
		stride := n
		ct := make([]byte, 4*stride)
		rand.Read(ct)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen [4]State1
		ptGen := make([]byte, 4*stride)
		for inst := range 4 {
			seedState1(&sGen[inst], seed)
			genericDecrypt1(&sGen[inst], ct[inst*stride:(inst+1)*stride], ptGen[inst*stride:(inst+1)*stride], padWord)
		}

		var sAsm State4
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			for j := range 4 {
				sAsm.a[i][j] = v
			}
		}
		ptAsm := make([]byte, 4*stride)
		sAsm.FastLoopDecrypt167(ct, ptAsm, stride, padByte)

		if !bytes.Equal(ptGen, ptAsm) {
			for i := range len(ptGen) {
				if ptGen[i] != ptAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ptGen[i], ptAsm[i])
				}
			}
		}
		for i := range 25 {
			for j := range 4 {
				if sAsm.a[i][j] != sGen[j].a[i] {
					t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], sAsm.a[i][j])
				}
			}
		}
	})

	t.Run("x8", func(t *testing.T) {
		stride := n
		ct := make([]byte, 8*stride)
		rand.Read(ct)
		seed := make([]byte, 200)
		rand.Read(seed)

		var sGen [8]State1
		ptGen := make([]byte, 8*stride)
		for inst := range 8 {
			seedState1(&sGen[inst], seed)
			genericDecrypt1(&sGen[inst], ct[inst*stride:(inst+1)*stride], ptGen[inst*stride:(inst+1)*stride], padWord)
		}

		var sAsm State8
		for i := range 25 {
			off := i * 8
			v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
			for j := range 8 {
				sAsm.a[i][j] = v
			}
		}
		ptAsm := make([]byte, 8*stride)
		sAsm.FastLoopDecrypt167(ct, ptAsm, stride, padByte)

		if !bytes.Equal(ptGen, ptAsm) {
			for i := range len(ptGen) {
				if ptGen[i] != ptAsm[i] {
					t.Fatalf("first difference at byte %d (offset %d in instance %d): gen=%02x asm=%02x",
						i, i%stride, i/stride, ptGen[i], ptAsm[i])
				}
			}
		}
		for i := range 25 {
			for j := range 8 {
				if sAsm.a[i][j] != sGen[j].a[i] {
					t.Fatalf("state lane %d inst %d: gen=%016x asm=%016x", i, j, sGen[j].a[i], sAsm.a[i][j])
				}
			}
		}
	})
}

func BenchmarkFastLoopEncrypt167(b *testing.B) {
	for _, size := range helperSizes {
		// Adjust sizes to rate 167.
		n := (size.n / Rate167) * Rate167
		if n == 0 {
			n = Rate167
		}

		in := makeInput(n)
		out := make([]byte, n)

		b.Run("x1/"+size.name, func(b *testing.B) {
			var s State1
			b.SetBytes(int64(n))
			for b.Loop() {
				s.Reset()
				s.FastLoopEncrypt167(in, out, 0x0B)
			}
		})

		in2 := makeInput(2 * n)
		out2 := make([]byte, 2*n)
		b.Run("x2/"+size.name, func(b *testing.B) {
			var s State2
			b.SetBytes(int64(2 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopEncrypt167(in2, out2, n, 0x0B)
			}
		})

		in4 := makeInput(4 * n)
		out4 := make([]byte, 4*n)
		b.Run("x4/"+size.name, func(b *testing.B) {
			var s State4
			b.SetBytes(int64(4 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopEncrypt167(in4, out4, n, 0x0B)
			}
		})

		in8 := makeInput(8 * n)
		out8 := make([]byte, 8*n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopEncrypt167(in8, out8, n, 0x0B)
			}
		})
	}
}

func BenchmarkFastLoopDecrypt167(b *testing.B) {
	for _, size := range helperSizes {
		n := (size.n / Rate167) * Rate167
		if n == 0 {
			n = Rate167
		}

		in := makeInput(n)
		out := make([]byte, n)

		b.Run("x1/"+size.name, func(b *testing.B) {
			var s State1
			b.SetBytes(int64(n))
			for b.Loop() {
				s.Reset()
				s.FastLoopDecrypt167(in, out, 0x0B)
			}
		})

		in2 := makeInput(2 * n)
		out2 := make([]byte, 2*n)
		b.Run("x2/"+size.name, func(b *testing.B) {
			var s State2
			b.SetBytes(int64(2 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopDecrypt167(in2, out2, n, 0x0B)
			}
		})

		in4 := makeInput(4 * n)
		out4 := make([]byte, 4*n)
		b.Run("x4/"+size.name, func(b *testing.B) {
			var s State4
			b.SetBytes(int64(4 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopDecrypt167(in4, out4, n, 0x0B)
			}
		})

		in8 := makeInput(8 * n)
		out8 := make([]byte, 8*n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * n))
			for b.Loop() {
				s.Reset()
				s.FastLoopDecrypt167(in8, out8, n, 0x0B)
			}
		})
	}
}
