package keccak

import "testing"

// Helper benchmark sizes: chosen to exercise the absorb loop at meaningful lengths.
// 168 = 1 stripe, 8192 = KT128 block size (~48 stripes), 65536 = large input.
var helperSizes = []struct {
	name string
	n    int
}{
	{"168B", 168},
	{"8KiB", 8192},
	{"64KiB", 65536},
}

func makeInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func BenchmarkFastLoopAbsorb168(b *testing.B) {
	for _, size := range helperSizes {
		in := makeInput(size.n)

		b.Run("x1/"+size.name, func(b *testing.B) {
			var s State1
			b.SetBytes(int64(size.n))
			for b.Loop() {
				s.Reset()
				s.fastLoopAbsorb168(in)
			}
		})

		in8 := makeInput(8 * size.n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * size.n))
			for b.Loop() {
				s.Reset()
				s.fastLoopAbsorb168(in8, size.n)
			}
		})
	}
}

func BenchmarkAbsorbFinal(b *testing.B) {
	// Use a 100-byte tail (typical partial block).
	tail := makeInput(100)

	b.Run("x1", func(b *testing.B) {
		var s State1
		for b.Loop() {
			s.Reset()
			s.absorbFinal(tail, 0x0B)
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s State8
		for b.Loop() {
			s.Reset()
			s.absorbFinal(tail, tail, tail, tail, tail, tail, tail, tail, 0x0B)
		}
	})
}

func BenchmarkAbsorbCVx8(b *testing.B) {
	var s8 State8
	for inst := range 8 {
		s8.a[0][inst] = uint64(inst + 1)
		s8.a[1][inst] = uint64(inst + 0x10)
		s8.a[2][inst] = uint64(inst + 0x20)
		s8.a[3][inst] = uint64(inst + 0x30)
	}

	b.Run("x8", func(b *testing.B) {
		var d State1
		b.SetBytes(8 * 32)
		for b.Loop() {
			d.Reset()
			d.AbsorbCVx8(&s8)
		}
	})

}
