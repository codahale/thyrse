package keccak

import "testing"

var sinkByte byte //nolint:gochecknoglobals

func BenchmarkPermute12Selected(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		var s State1
		b.SetBytes(StateBytes)
		for b.Loop() {
			s.Permute12()
		}
	})

	b.Run("x2", func(b *testing.B) {
		var s State2
		b.SetBytes(2 * StateBytes)
		for b.Loop() {
			s.Permute12()
		}
	})

	b.Run("x4", func(b *testing.B) {
		var s State4
		b.SetBytes(4 * StateBytes)
		for b.Loop() {
			s.Permute12()
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s State8
		b.SetBytes(8 * StateBytes)
		for b.Loop() {
			s.Permute12()
		}
	})
}

func BenchmarkPermute12Generic(b *testing.B) {
	b.Run("x1", func(b *testing.B) {
		var s State1
		b.SetBytes(StateBytes)
		for b.Loop() {
			permute12x1Generic(&s)
		}
	})

	b.Run("x2", func(b *testing.B) {
		var s State2
		b.SetBytes(2 * StateBytes)
		for b.Loop() {
			permute12x2Generic(&s)
		}
	})

	b.Run("x4", func(b *testing.B) {
		var s State4
		b.SetBytes(4 * StateBytes)
		for b.Loop() {
			permute12x4Generic(&s)
		}
	})

	b.Run("x8", func(b *testing.B) {
		var s State8
		b.SetBytes(8 * StateBytes)
		for b.Loop() {
			permute12x8Generic(&s)
		}
	})
}

func BenchmarkHelpersState1Rate168(b *testing.B) {
	in := make([]byte, 168)
	out := make([]byte, 168)
	var s State1

	b.Run("absorb", func(b *testing.B) {
		b.SetBytes(168)
		for b.Loop() {
			s.AbsorbStripe(168, in)
		}
	})

	b.Run("overwrite", func(b *testing.B) {
		b.SetBytes(168)
		for b.Loop() {
			s.OverwriteStripe(168, in)
		}
	})

	b.Run("squeeze", func(b *testing.B) {
		b.SetBytes(168)
		for b.Loop() {
			s.SqueezeStripe(168, out)
		}
		sinkByte ^= out[0]
	})

	b.Run("overwrite_encrypt", func(b *testing.B) {
		b.SetBytes(168)
		for b.Loop() {
			s.OverwriteEncryptStripe(168, out, in)
		}
		sinkByte ^= out[0]
	})

	b.Run("overwrite_decrypt", func(b *testing.B) {
		b.SetBytes(168)
		for b.Loop() {
			s.OverwriteDecryptStripe(168, out, in)
		}
		sinkByte ^= out[0]
	})
}

func BenchmarkHelpersState2Rate168(b *testing.B) {
	in := make([]byte, 2*168)
	out := make([]byte, 2*168)
	var s State2

	b.Run("absorb", func(b *testing.B) {
		b.SetBytes(2 * 168)
		for b.Loop() {
			s.AbsorbStripe(168, in)
		}
	})

	b.Run("squeeze", func(b *testing.B) {
		b.SetBytes(2 * 168)
		for b.Loop() {
			s.SqueezeStripe(168, out)
		}
		sinkByte ^= out[0]
	})

	b.Run("overwrite_encrypt", func(b *testing.B) {
		b.SetBytes(2 * 168)
		for b.Loop() {
			s.OverwriteEncryptStripe(168, out, in)
		}
		sinkByte ^= out[0]
	})
}

func BenchmarkMixedState1Rate168(b *testing.B) {
	in := make([]byte, 168)
	out := make([]byte, 168)
	var s State1
	b.SetBytes(168)

	for b.Loop() {
		s.AbsorbStripe(168, in)
		s.Permute12()
		s.SqueezeStripe(168, out)
	}

	sinkByte ^= out[0]
}

func BenchmarkMixedState2Rate168(b *testing.B) {
	in := make([]byte, 2*168)
	out := make([]byte, 2*168)
	var s State2
	b.SetBytes(2 * 168)

	for b.Loop() {
		s.AbsorbStripe(168, in)
		s.Permute12()
		s.SqueezeStripe(168, out)
	}

	sinkByte ^= out[0]
}
