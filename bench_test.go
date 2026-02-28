package thyrse

import (
	"bytes"
	"io"
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

func BenchmarkDerive(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			out := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Derive("output", out[:0], size.N)
			}
		})
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N+TagSize)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Seal("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N+TagSize)
			// Pre-seal to get valid sealed data.
			sealed := p.Clone().Seal("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = p.Clone().Open("msg", plaintext[:0], sealed)
			}
		})
	}
}

func BenchmarkMask(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Mask("msg", ciphertext[:0], plaintext)
			}
		})
	}
}

func BenchmarkUnmask(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)
			p.Clone().Mask("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Clone().Unmask("msg", plaintext[:0], ciphertext)
			}
		})
	}
}

func BenchmarkMix(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Mix("data", data)
			}
		})
	}
}

func BenchmarkMixStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				_ = p.MixStream("data", bytes.NewReader(data))
			}
		})
	}
}

func BenchmarkMixWriter(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				mw := p.MixWriter("data")
				_, _ = io.Copy(mw, bytes.NewReader(data))
				_ = mw.Close()
			}
		})
	}
}

func BenchmarkMaskStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				ms := p.MaskStream("msg")
				ms.XORKeyStream(ciphertext, plaintext)
				_ = ms.Close()
			}
		})
	}
}

func BenchmarkUnmaskStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)
			p.Clone().Mask("msg", ciphertext[:0], plaintext)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				us := p.Clone().UnmaskStream("msg")
				us.XORKeyStream(plaintext, ciphertext)
				_ = us.Close()
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
