package aead_test

import (
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/basic/aead"
)

func BenchmarkAEAD_Seal(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	c := aead.New("com.example.benchmark", key, 16)

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			plaintext := make([]byte, size.N)
			dst := make([]byte, 0, size.N+c.Overhead())

			b.ReportAllocs()
			b.SetBytes(int64(size.N))
			b.ResetTimer()

			for b.Loop() {
				_ = c.Seal(dst[:0], nonce, plaintext, ad)
			}
		})
	}
}

func BenchmarkAEAD_Open(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	c := aead.New("com.example.benchmark", key, 16)

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			plaintext := make([]byte, size.N)
			ciphertext := c.Seal(nil, nonce, plaintext, ad)
			dst := make([]byte, 0, size.N)

			b.ReportAllocs()
			b.SetBytes(int64(size.N))
			b.ResetTimer()

			for b.Loop() {
				_, _ = c.Open(dst[:0], nonce, ciphertext, ad)
			}
		})
	}
}
