package thyrse

import (
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
)

func BenchmarkProtocol_Derive(b *testing.B) {
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

func BenchmarkProtocol_Seal(b *testing.B) {
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

func BenchmarkProtocol_Open(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N+TagSize)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				_, _ = p.Open("msg", plaintext[:0], ciphertext)
			}
		})
	}
}

func BenchmarkProtocol_Mask(b *testing.B) {
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

func BenchmarkProtocol_Unmask(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				p.Unmask("msg", plaintext[:0], ciphertext)
			}
		})
	}
}

func BenchmarkProtocol_Mix(b *testing.B) {
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

func BenchmarkProtocol_MaskStream(b *testing.B) {
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

func BenchmarkProtocol_UnmaskStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			plaintext := make([]byte, size.N)
			ciphertext := make([]byte, size.N)

			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				us := p.UnmaskStream("msg")
				us.XORKeyStream(plaintext, ciphertext)
				_ = us.Close()
			}
		})
	}
}

func BenchmarkProtocol_Ratchet(b *testing.B) {
	p := New("bench")
	b.ReportAllocs()
	for b.Loop() {
		p.Ratchet("ratchet")
	}
}

func BenchmarkProtocol_Fork(b *testing.B) {
	p := New("bench")
	values := [][]byte{[]byte("alice"), []byte("bob")}
	b.ReportAllocs()
	for b.Loop() {
		p.ForkN("role", values...)
	}
}
