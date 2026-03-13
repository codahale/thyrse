package keccak

import (
	"bytes"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

// TestFastLoopEncryptDecrypt168 verifies round-trip: encrypt then decrypt
// recovers the original plaintext and produces identical final states.
func TestFastLoopEncryptDecrypt168(t *testing.T) {
	const nBlocks = 5
	const blockSize = Rate

	t.Run("x1", func(t *testing.T) {
		drbg := testdata.New("helpers168 rt x1")
		n := nBlocks * blockSize
		pt := drbg.Data(n)
		ct := make([]byte, n)
		recovered := make([]byte, n)

		var sEnc, sDec State1
		seed := drbg.Data(200)
		for i := range 25 {
			v := uint64(seed[i*8]) | uint64(seed[i*8+1])<<8 | uint64(seed[i*8+2])<<16 | uint64(seed[i*8+3])<<24 |
				uint64(seed[i*8+4])<<32 | uint64(seed[i*8+5])<<40 | uint64(seed[i*8+6])<<48 | uint64(seed[i*8+7])<<56
			sEnc.a[i] = v
			sDec.a[i] = v
		}

		if got, want := sEnc.fastLoopEncrypt168(pt, ct), n; got != want {
			t.Fatalf("FastLoopEncrypt168() = %d, want %d", got, want)
		}
		if got, want := sDec.fastLoopDecrypt168(ct, recovered), n; got != want {
			t.Fatalf("FastLoopDecrypt168() = %d, want %d", got, want)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatal("round-trip failed: plaintext != recovered")
		}
		if sEnc.a != sDec.a {
			t.Fatal("final states differ after encrypt/decrypt")
		}
	})

	t.Run("x8", func(t *testing.T) {
		drbg := testdata.New("helpers168 rt x8")
		n := nBlocks * blockSize
		stride := n
		pt := drbg.Data(8 * stride)
		ct := make([]byte, 8*stride)
		recovered := make([]byte, 8*stride)

		var sEnc, sDec State8
		seed := drbg.Data(1600)
		for i := range 25 {
			for j := range 8 {
				off := (i*8 + j) * 8
				v := uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
					uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
				sEnc.a[i][j] = v
				sDec.a[i][j] = v
			}
		}

		if got, want := sEnc.fastLoopEncrypt168(pt, ct, stride), n; got != want {
			t.Fatalf("FastLoopEncrypt168() = %d, want %d", got, want)
		}
		if got, want := sDec.fastLoopDecrypt168(ct, recovered, stride), n; got != want {
			t.Fatalf("FastLoopDecrypt168() = %d, want %d", got, want)
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

// genericEncrypt1 runs x1 encrypt using pure Go logic (168-byte blocks, no padding).
func genericEncrypt1(s *State1, pt, ct []byte) {
	for off := 0; off < len(pt); off += Rate {
		for lane := range 21 {
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
		s.Permute12()
	}
}

// genericDecrypt1 runs x1 decrypt using pure Go logic (168-byte blocks, no padding).
func genericDecrypt1(s *State1, ct, pt []byte) {
	for off := 0; off < len(ct); off += Rate {
		for lane := range 21 {
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
		s.Permute12()
	}
}

// TestFastLoopEncrypt168CrossValidation verifies the assembly encrypt matches
// the Go generic fallback by running both with identical inputs and comparing outputs.
func TestFastLoopEncrypt168CrossValidation(t *testing.T) {
	const nBlocks = 3
	const n = nBlocks * Rate

	t.Run("x1", func(t *testing.T) {
		drbg := testdata.New("xval enc x1")
		pt := drbg.Data(n)
		seed := drbg.Data(200)

		var sGen State1
		seedState1(&sGen, seed)
		ctGen := make([]byte, n)
		genericEncrypt1(&sGen, pt, ctGen)

		var sAsm State1
		seedState1(&sAsm, seed)
		ctAsm := make([]byte, n)
		sAsm.fastLoopEncrypt168(pt, ctAsm)

		if !bytes.Equal(ctGen, ctAsm) {
			t.Fatal("assembly output differs from generic")
		}
		if sGen.a != sAsm.a {
			t.Fatal("final state differs")
		}
	})

	t.Run("x8", func(t *testing.T) {
		drbg := testdata.New("xval enc x8")
		stride := n
		pt := drbg.Data(8 * stride)

		// Distinct seed per instance to detect state pointer corruption.
		var seeds [8][]byte
		for inst := range 8 {
			seeds[inst] = drbg.Data(200)
		}

		var sGen [8]State1
		ctGen := make([]byte, 8*stride)
		for inst := range 8 {
			seedState1(&sGen[inst], seeds[inst])
			genericEncrypt1(&sGen[inst], pt[inst*stride:(inst+1)*stride], ctGen[inst*stride:(inst+1)*stride])
		}

		var sAsm State8
		for i := range 25 {
			for j := range 8 {
				off := i * 8
				v := uint64(seeds[j][off]) | uint64(seeds[j][off+1])<<8 | uint64(seeds[j][off+2])<<16 | uint64(seeds[j][off+3])<<24 |
					uint64(seeds[j][off+4])<<32 | uint64(seeds[j][off+5])<<40 | uint64(seeds[j][off+6])<<48 | uint64(seeds[j][off+7])<<56
				sAsm.a[i][j] = v
			}
		}
		ctAsm := make([]byte, 8*stride)
		sAsm.fastLoopEncrypt168(pt, ctAsm, stride)

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

// TestFastLoopDecrypt168CrossValidation verifies the assembly decrypt matches
// the Go generic fallback.
func TestFastLoopDecrypt168CrossValidation(t *testing.T) {
	const nBlocks = 3
	const n = nBlocks * Rate

	t.Run("x1", func(t *testing.T) {
		drbg := testdata.New("xval dec x1")
		ct := drbg.Data(n)
		seed := drbg.Data(200)

		var sGen State1
		seedState1(&sGen, seed)
		ptGen := make([]byte, n)
		genericDecrypt1(&sGen, ct, ptGen)

		var sAsm State1
		seedState1(&sAsm, seed)
		ptAsm := make([]byte, n)
		sAsm.fastLoopDecrypt168(ct, ptAsm)

		if !bytes.Equal(ptGen, ptAsm) {
			t.Fatal("assembly output differs from generic")
		}
		if sGen.a != sAsm.a {
			t.Fatal("final state differs")
		}
	})

	t.Run("x8", func(t *testing.T) {
		drbg := testdata.New("xval dec x8")
		stride := n
		ct := drbg.Data(8 * stride)

		// Distinct seed per instance to detect state pointer corruption.
		var seeds [8][]byte
		for inst := range 8 {
			seeds[inst] = drbg.Data(200)
		}

		var sGen [8]State1
		ptGen := make([]byte, 8*stride)
		for inst := range 8 {
			seedState1(&sGen[inst], seeds[inst])
			genericDecrypt1(&sGen[inst], ct[inst*stride:(inst+1)*stride], ptGen[inst*stride:(inst+1)*stride])
		}

		var sAsm State8
		for i := range 25 {
			for j := range 8 {
				off := i * 8
				v := uint64(seeds[j][off]) | uint64(seeds[j][off+1])<<8 | uint64(seeds[j][off+2])<<16 | uint64(seeds[j][off+3])<<24 |
					uint64(seeds[j][off+4])<<32 | uint64(seeds[j][off+5])<<40 | uint64(seeds[j][off+6])<<48 | uint64(seeds[j][off+7])<<56
				sAsm.a[i][j] = v
			}
		}
		ptAsm := make([]byte, 8*stride)
		sAsm.fastLoopDecrypt168(ct, ptAsm, stride)

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

func BenchmarkFastLoopEncrypt168(b *testing.B) {
	for _, size := range helperSizes {
		n := (size.n / Rate) * Rate
		if n == 0 {
			n = Rate
		}

		in := makeInput(n)
		out := make([]byte, n)

		b.Run("x1/"+size.name, func(b *testing.B) {
			var s State1
			b.SetBytes(int64(n))
			for b.Loop() {
				s.Reset()
				s.fastLoopEncrypt168(in, out)
			}
		})

		in8 := makeInput(8 * n)
		out8 := make([]byte, 8*n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * n))
			for b.Loop() {
				s.Reset()
				s.fastLoopEncrypt168(in8, out8, n)
			}
		})
	}
}

func BenchmarkFastLoopDecrypt168(b *testing.B) {
	for _, size := range helperSizes {
		n := (size.n / Rate) * Rate
		if n == 0 {
			n = Rate
		}

		in := makeInput(n)
		out := make([]byte, n)

		b.Run("x1/"+size.name, func(b *testing.B) {
			var s State1
			b.SetBytes(int64(n))
			for b.Loop() {
				s.Reset()
				s.fastLoopDecrypt168(in, out)
			}
		})

		in8 := makeInput(8 * n)
		out8 := make([]byte, 8*n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * n))
			for b.Loop() {
				s.Reset()
				s.fastLoopDecrypt168(in8, out8, n)
			}
		})
	}
}
