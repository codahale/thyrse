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

func BenchmarkAbsorbCVx8(b *testing.B) {
	var s8 State8
	for inst := range 8 {
		s8.a[0][inst] = uint64(inst + 1)
		s8.a[1][inst] = uint64(inst + 0x10)
		s8.a[2][inst] = uint64(inst + 0x20)
		s8.a[3][inst] = uint64(inst + 0x30)
	}

	b.Run("x8", func(b *testing.B) {
		var d Duplex
		b.SetBytes(8 * 32)
		for b.Loop() {
			d.Reset()
			d.AbsorbCVx8(&s8)
		}
	})

	b.Run("x4", func(b *testing.B) {
		var s4 State4
		for inst := range 4 {
			s4.a[0][inst] = s8.a[0][inst]
			s4.a[1][inst] = s8.a[1][inst]
			s4.a[2][inst] = s8.a[2][inst]
			s4.a[3][inst] = s8.a[3][inst]
		}
		var d Duplex
		b.SetBytes(4 * 32)
		for b.Loop() {
			d.Reset()
			d.AbsorbCVx4(&s4)
		}
	})

	b.Run("x2", func(b *testing.B) {
		var s2 State2
		for inst := range 2 {
			s2.a[0][inst] = s8.a[0][inst]
			s2.a[1][inst] = s8.a[1][inst]
			s2.a[2][inst] = s8.a[2][inst]
			s2.a[3][inst] = s8.a[3][inst]
		}
		var d Duplex
		b.SetBytes(2 * 32)
		for b.Loop() {
			d.Reset()
			d.AbsorbCVx2(&s2)
		}
	})
}
