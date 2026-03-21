package keccak

import "testing"

func BenchmarkPermute12Selected(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		var s State1
		b.SetBytes(stateBytes)
		for b.Loop() {
			s.permute12()
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s state8
		b.SetBytes(8 * stateBytes)
		for b.Loop() {
			s.permute12()
		}
	})
}

func BenchmarkPermute12Generic(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		var s State1
		b.SetBytes(stateBytes)
		for b.Loop() {
			permute12x1Generic(&s)
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s state8
		b.SetBytes(8 * stateBytes)
		for b.Loop() {
			permute12x8Generic(&s)
		}
	})
}
