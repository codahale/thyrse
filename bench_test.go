package thyrse

import (
	"bytes"
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

func BenchmarkDerive(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			out := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p.Derive("output", out[:0], size)
			}
		})
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size+TagSize)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p.Seal("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size+TagSize)
			// Pre-seal to get valid sealed data.
			sealed := p.Clone().Seal("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = p.Clone().Open("msg", plaintext[:0], sealed)
			}
		})
	}
}

func BenchmarkMask(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p.Mask("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkUnmask(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size)
			ciphertext := make([]byte, size)
			p.Clone().Mask("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p.Clone().Unmask("msg", plaintext[:0], ciphertext)
			}
		})
	}
}

func BenchmarkMix(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				p.Mix("data", data)
			}
		})
	}
}

func BenchmarkMixStream(b *testing.B) {
	for _, size := range sizes {
		b.Run(sizeName(size), func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for b.Loop() {
				_ = p.MixStream("data", bytes.NewReader(data))
			}
		})
	}
}

func BenchmarkRatchet(b *testing.B) {
	p := New("bench")
	b.ReportAllocs()
	for b.Loop() {
		p.Ratchet("ratchet")
	}
}

func BenchmarkFork(b *testing.B) {
	p := New("bench")
	values := [][]byte{[]byte("alice"), []byte("bob")}
	b.ReportAllocs()
	for b.Loop() {
		p.Fork("role", values...)
	}
}
