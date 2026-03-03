package keccak

import "testing"

func BenchmarkPermute12x1(b *testing.B) {
	var s State1
	for b.Loop() {
		s.Permute12()
	}
}

func BenchmarkPermute12x2(b *testing.B) {
	var s State2
	for b.Loop() {
		s.Permute12()
	}
}

func BenchmarkPermute12x4(b *testing.B) {
	var s State4
	for b.Loop() {
		s.Permute12()
	}
}

func BenchmarkPermute12x8(b *testing.B) {
	var s State8
	for b.Loop() {
		s.Permute12()
	}
}

func BenchmarkOverwriteEncryptStripe168(b *testing.B) {
	var s State1
	pt := make([]byte, 168)
	ct := make([]byte, 168)
	for b.Loop() {
		s.OverwriteEncryptStripe(168, ct, pt)
	}
}

func BenchmarkSqueezeStripe168(b *testing.B) {
	var s State1
	out := make([]byte, 168)
	for b.Loop() {
		s.SqueezeStripe(168, out)
	}
}
