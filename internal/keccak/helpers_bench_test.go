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
				s.FastLoopAbsorb168(in)
			}
		})

		in2 := makeInput(2 * size.n)
		b.Run("x2/"+size.name, func(b *testing.B) {
			var s State2
			b.SetBytes(int64(2 * size.n))
			for b.Loop() {
				s.Reset()
				s.FastLoopAbsorb168(in2, size.n)
			}
		})

		in4 := makeInput(4 * size.n)
		b.Run("x4/"+size.name, func(b *testing.B) {
			var s State4
			b.SetBytes(int64(4 * size.n))
			for b.Loop() {
				s.Reset()
				s.FastLoopAbsorb168(in4, size.n)
			}
		})

		in8 := makeInput(8 * size.n)
		b.Run("x8/"+size.name, func(b *testing.B) {
			var s State8
			b.SetBytes(int64(8 * size.n))
			for b.Loop() {
				s.Reset()
				s.FastLoopAbsorb168(in8, size.n)
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
			s.AbsorbFinal(tail, 0x0B)
		}
	})

	b.Run("x2", func(b *testing.B) {
		var s State2
		for b.Loop() {
			s.Reset()
			s.AbsorbFinal(tail, tail, 0x0B)
		}
	})

	b.Run("x4", func(b *testing.B) {
		var s State4
		for b.Loop() {
			s.Reset()
			s.AbsorbFinal(tail, tail, tail, tail, 0x0B)
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s State8
		for b.Loop() {
			s.Reset()
			s.AbsorbFinal(tail, tail, tail, tail, tail, tail, tail, tail, 0x0B)
		}
	})
}
