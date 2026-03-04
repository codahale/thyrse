//go:build arm64 && !purego

package keccak

import "testing"

func directPermute1ARM64(s *State1) { p1600(s) }

func directPermute2ARM64(s *State2) { p1600x2Lane(s) }

func BenchmarkPermute12LowLevelARM64(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		b.Run("direct_backend", func(b *testing.B) {
			var s State1
			b.SetBytes(StateBytes)
			for b.Loop() {
				directPermute1ARM64(&s)
			}
		})
		b.Run("arch_dispatch", func(b *testing.B) {
			var s State1
			b.SetBytes(StateBytes)
			for b.Loop() {
				if !permute12x1Arch(&s) {
					permute12x1Generic(&s)
				}
			}
		})
		b.Run("method", func(b *testing.B) {
			var s State1
			b.SetBytes(StateBytes)
			for b.Loop() {
				s.Permute12()
			}
		})
	})

	b.Run("x2", func(b *testing.B) {
		b.Run("direct_backend", func(b *testing.B) {
			var s State2
			b.SetBytes(2 * StateBytes)
			for b.Loop() {
				directPermute2ARM64(&s)
			}
		})
		b.Run("arch_dispatch", func(b *testing.B) {
			var s State2
			b.SetBytes(2 * StateBytes)
			for b.Loop() {
				if !permute12x2Arch(&s) {
					permute12x2Generic(&s)
				}
			}
		})
		b.Run("method", func(b *testing.B) {
			var s State2
			b.SetBytes(2 * StateBytes)
			for b.Loop() {
				s.Permute12()
			}
		})
	})

	b.Run("x4", func(b *testing.B) {
		b.Run("arch_dispatch", func(b *testing.B) {
			var s State4
			b.SetBytes(4 * StateBytes)
			for b.Loop() {
				if !permute12x4Arch(&s) {
					permute12x4Generic(&s)
				}
			}
		})
		b.Run("method", func(b *testing.B) {
			var s State4
			b.SetBytes(4 * StateBytes)
			for b.Loop() {
				s.Permute12()
			}
		})
	})

	b.Run("x8", func(b *testing.B) {
		b.Run("arch_dispatch", func(b *testing.B) {
			var s State8
			b.SetBytes(8 * StateBytes)
			for b.Loop() {
				if !permute12x8Arch(&s) {
					permute12x8Generic(&s)
				}
			}
		})
		b.Run("method", func(b *testing.B) {
			var s State8
			b.SetBytes(8 * StateBytes)
			for b.Loop() {
				s.Permute12()
			}
		})
	})
}
