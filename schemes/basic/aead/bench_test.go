package aead_test

import (
	"testing"

	"github.com/codahale/thyrse/schemes/basic/aead"
)

func BenchmarkAEAD_Seal(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	c := aead.New("com.example.benchmark", key, 16)

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			plaintext := make([]byte, length.n)
			dst := make([]byte, 0, length.n+c.Overhead())

			b.ReportAllocs()
			b.SetBytes(int64(length.n))
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

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			plaintext := make([]byte, length.n)
			ciphertext := c.Seal(nil, nonce, plaintext, ad)
			dst := make([]byte, 0, length.n)

			b.ReportAllocs()
			b.SetBytes(int64(length.n))
			b.ResetTimer()

			for b.Loop() {
				_, _ = c.Open(dst[:0], nonce, ciphertext, ad)
			}
		})
	}
}

var lengths = []struct {
	name string
	n    int
}{
	{"16B", 16},
	{"32B", 32},
	{"64B", 64},
	{"128B", 128},
	{"256B", 256},
	{"1KiB", 1024},
	{"16KiB", 16 * 1024},
	{"1MiB", 1024 * 1024},
}
