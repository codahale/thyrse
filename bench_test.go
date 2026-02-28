package thyrse

import (
	"fmt"
	"testing"
)

var sizes = []int{
	1,
	64,
	1 << 10,  // 1 KiB
	8 << 10,  // 8 KiB
	64 << 10, // 64 KiB
	1 << 20,  // 1 MiB
}

func sizeName(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%dKiB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// newSeeded returns a Protocol with Init + Mix(key) already applied.
func newSeeded() *Protocol {
	p := New("bench")
	p.Mix("key", make([]byte, 32))
	return p
}

func BenchmarkDerive(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			out := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := newSeeded()
				p.Derive("output", out[:0], size)
			}
		})
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size+TagSize)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := newSeeded()
				p.Seal("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size+TagSize)
			// Pre-seal to get valid sealed data.
			p := newSeeded()
			sealed := p.Seal("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := newSeeded()
				_, _ = p.Open("msg", plaintext[:0], sealed)
			}
		})
	}
}

func BenchmarkMask(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := newSeeded()
				p.Mask("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkUnmask(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size)
			p := newSeeded()
			p.Mask("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := newSeeded()
				p.Unmask("msg", plaintext[:0], ciphertext)
			}
		})
	}
}

func BenchmarkMix(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := New("bench")
				p.Mix("data", data)
			}
		})
	}
}

func BenchmarkMixStream(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p := New("bench")
				p.MixStream("data", data)
			}
		})
	}
}

func BenchmarkRatchet(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		p := newSeeded()
		p.Ratchet("ratchet")
	}
}

func BenchmarkFork(b *testing.B) {
	values := [][]byte{[]byte("alice"), []byte("bob")}
	b.ReportAllocs()
	for b.Loop() {
		p := newSeeded()
		p.Fork("role", values...)
	}
}
