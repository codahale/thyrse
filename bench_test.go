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

func BenchmarkProtocol_MaskStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			for _, chunkSize := range streamChunkSizes(size.N) {
				b.Run(chunkSize.name, func(b *testing.B) {
					p := New("bench")
					plaintext := make([]byte, size.N)
					ciphertext := make([]byte, size.N)
					b.SetBytes(int64(size.N))
					b.ReportAllocs()
					for b.Loop() {
						s := p.MaskStream("msg")
						for off := 0; off < len(plaintext); off += chunkSize.n {
							end := min(off+chunkSize.n, len(plaintext))
							s.XORKeyStream(ciphertext[off:end], plaintext[off:end])
						}
						_ = s.Close()
					}
				})
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

func BenchmarkProtocol_UnmaskStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			for _, chunkSize := range streamChunkSizes(size.N) {
				b.Run(chunkSize.name, func(b *testing.B) {
					p := New("bench")
					plaintext := make([]byte, size.N)
					ciphertext := make([]byte, size.N)

					b.SetBytes(int64(size.N))
					b.ReportAllocs()
					for b.Loop() {
						s := p.UnmaskStream("msg")
						for off := 0; off < len(ciphertext); off += chunkSize.n {
							end := min(off+chunkSize.n, len(ciphertext))
							s.XORKeyStream(plaintext[off:end], ciphertext[off:end])
						}
						_ = s.Close()
					}
				})
			}
		})
	}
}

type streamChunkSize struct {
	name string
	n    int
}

func streamChunkSizes(n int) []streamChunkSize {
	chunks := []streamChunkSize{{name: "one-shot", n: max(n, 1)}}
	if n > 1024 {
		chunks = append(chunks, streamChunkSize{name: "1KiB-chunks", n: 1024})
	}
	return chunks
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

func BenchmarkProtocol_MixStream(b *testing.B) {
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			p := New("bench")
			data := make([]byte, size.N)
			b.SetBytes(int64(size.N))
			b.ReportAllocs()
			for b.Loop() {
				w := p.MixWriter("data")
				_, _ = w.Write(data)
				_ = w.Close()
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
