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
	const blockSize = rate167

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

// TestFastLoopEncrypt167CrossValidation verifies the assembly encrypt matches
// the Go generic fallback by running both with identical inputs and comparing outputs.
func TestFastLoopEncrypt167CrossValidation(t *testing.T) {
	const padByte byte = 0x07
	const nBlocks = 3
	const n = nBlocks * rate167

	t.Run("x1", func(t *testing.T) {
		pt := make([]byte, n)
		rand.Read(pt)
		seed := make([]byte, 200)
		rand.Read(seed)

		// Generic fallback.
		var sGen State1
		for i := range 25 {
			off := i * 8
			sGen.a[i] = uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
		}
		ctGen := make([]byte, n)
		padWord := uint64(padByte) << 56
		// Run generic by forcing arch to fail.
		for off := 0; off < n; off += rate167 {
			for lane := range 20 {
				base := lane << 3
				w := uint64(pt[off+base]) | uint64(pt[off+base+1])<<8 | uint64(pt[off+base+2])<<16 | uint64(pt[off+base+3])<<24 |
					uint64(pt[off+base+4])<<32 | uint64(pt[off+base+5])<<40 | uint64(pt[off+base+6])<<48 | uint64(pt[off+base+7])<<56
				sGen.a[lane] ^= w
				v := sGen.a[lane]
				ctGen[off+base] = byte(v)
				ctGen[off+base+1] = byte(v >> 8)
				ctGen[off+base+2] = byte(v >> 16)
				ctGen[off+base+3] = byte(v >> 24)
				ctGen[off+base+4] = byte(v >> 32)
				ctGen[off+base+5] = byte(v >> 40)
				ctGen[off+base+6] = byte(v >> 48)
				ctGen[off+base+7] = byte(v >> 56)
			}
			w := loadPartialLE(pt[off+160 : off+167])
			sGen.a[20] ^= w
			storePartialLE(ctGen[off+160:off+167], sGen.a[20])
			sGen.a[20] ^= padWord
			sGen.Permute12()
		}

		// Full method (uses arch if available).
		var sAsm State1
		for i := range 25 {
			off := i * 8
			sAsm.a[i] = uint64(seed[off]) | uint64(seed[off+1])<<8 | uint64(seed[off+2])<<16 | uint64(seed[off+3])<<24 |
				uint64(seed[off+4])<<32 | uint64(seed[off+5])<<40 | uint64(seed[off+6])<<48 | uint64(seed[off+7])<<56
		}
		ctAsm := make([]byte, n)
		sAsm.FastLoopEncrypt167(pt, ctAsm, padByte)

		if !bytes.Equal(ctGen, ctAsm) {
			t.Fatal("encrypt x1: assembly output differs from generic")
		}
		if sGen.a != sAsm.a {
			t.Fatal("encrypt x1: final state differs")
		}
	})
}

func BenchmarkFastLoopEncrypt167(b *testing.B) {
	for _, size := range helperSizes {
		// Adjust sizes to rate 167.
		n := (size.n / rate167) * rate167
		if n == 0 {
			n = rate167
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
		n := (size.n / rate167) * rate167
		if n == 0 {
			n = rate167
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
