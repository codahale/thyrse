//go:build amd64 && !purego

package keccak

import (
	"testing"

	"github.com/klauspost/cpuid/v2"
)

func BenchmarkPermute12LowLevelAMD64(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		b.Run("direct_backend", func(b *testing.B) {
			var s State1
			b.SetBytes(StateBytes)
			switch {
			case forcedBackend == "generic":
				for b.Loop() {
					permute12x1Generic(&s)
				}
			case cpuid.CPU.Has(cpuid.BMI1) && cpuid.CPU.Has(cpuid.BMI2):
				for b.Loop() {
					p1600(&s)
				}
			default:
				for b.Loop() {
					permute12x1Generic(&s)
				}
			}
		})
		b.Run("selected_fn", func(b *testing.B) {
			var s State1
			b.SetBytes(StateBytes)
			for b.Loop() {
				selected.permute1(&s)
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
			switch {
			case forcedBackend == "amd64_avx512":
				for b.Loop() {
					p1600x2LaneAVX512(&s)
				}
			case forcedBackend == "amd64_avx2" || forcedBackend == "amd64_sse2":
				for b.Loop() {
					p1600x2Lane(&s)
				}
			case forcedBackend == "generic":
				for b.Loop() {
					permute12x2Generic(&s)
				}
			case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
				for b.Loop() {
					p1600x2LaneAVX512(&s)
				}
			default:
				for b.Loop() {
					p1600x2Lane(&s)
				}
			}
		})
		b.Run("direct_wrapper", func(b *testing.B) {
			var s State2
			b.SetBytes(2 * StateBytes)
			for b.Loop() {
				permute12x2AMD64(&s)
			}
		})
		b.Run("selected_fn", func(b *testing.B) {
			var s State2
			b.SetBytes(2 * StateBytes)
			for b.Loop() {
				selected.permute2(&s)
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
		b.Run("direct_backend", func(b *testing.B) {
			var s State4
			b.SetBytes(4 * StateBytes)
			switch {
			case forcedBackend == "amd64_avx512":
				for b.Loop() {
					p1600x4LaneAVX512(&s)
				}
			case forcedBackend == "amd64_avx2" || forcedBackend == "amd64_sse2":
				for b.Loop() {
					p1600x4Lane(&s)
				}
			case forcedBackend == "generic":
				for b.Loop() {
					permute12x4Generic(&s)
				}
			case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
				for b.Loop() {
					p1600x4LaneAVX512(&s)
				}
			case cpuid.CPU.Has(cpuid.AVX2):
				for b.Loop() {
					p1600x4Lane(&s)
				}
			default:
				for b.Loop() {
					permute12x4SSE2FallbackAMD64(&s)
				}
			}
		})
		b.Run("direct_wrapper", func(b *testing.B) {
			var s State4
			b.SetBytes(4 * StateBytes)
			for b.Loop() {
				permute12x4AMD64(&s)
			}
		})
		b.Run("selected_fn", func(b *testing.B) {
			var s State4
			b.SetBytes(4 * StateBytes)
			for b.Loop() {
				selected.permute4(&s)
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
		b.Run("direct_backend", func(b *testing.B) {
			var s State8
			b.SetBytes(8 * StateBytes)
			switch {
			case forcedBackend == "amd64_avx512":
				for b.Loop() {
					p1600x8AVX512State(&s)
				}
			case forcedBackend == "amd64_avx2" || forcedBackend == "amd64_sse2":
				for b.Loop() {
					p1600x8Lane(&s)
				}
			case forcedBackend == "generic":
				for b.Loop() {
					permute12x8Generic(&s)
				}
			case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
				for b.Loop() {
					p1600x8AVX512State(&s)
				}
			case cpuid.CPU.Has(cpuid.AVX2):
				for b.Loop() {
					p1600x8Lane(&s)
				}
			default:
				for b.Loop() {
					permute12x8SSE2FallbackAMD64(&s)
				}
			}
		})
		b.Run("direct_wrapper", func(b *testing.B) {
			var s State8
			b.SetBytes(8 * StateBytes)
			for b.Loop() {
				permute12x8AMD64(&s)
			}
		})
		b.Run("selected_fn", func(b *testing.B) {
			var s State8
			b.SetBytes(8 * StateBytes)
			for b.Loop() {
				selected.permute8(&s)
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
