package thyrse_test

import (
	"bytes"
	"testing"

	"github.com/codahale/thyrse"
	"github.com/codahale/thyrse/internal/testdata"
)

func BenchmarkSchemeHash(b *testing.B) {
	hash := func(message, dst []byte) []byte {
		protocol := thyrse.New("hash")
		_ = protocol.MixDigest("message", bytes.NewReader(message))
		return protocol.Derive("digest", dst, 32)
	}

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			input := make([]byte, size.N)
			digest := make([]byte, 32)
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				hash(input, digest[:0])
			}
		})
	}
}

func BenchmarkSchemePRF(b *testing.B) {
	prf := func(key, output []byte) []byte {
		protocol := thyrse.New("prf")
		protocol.Mix("key", key)
		return protocol.Derive("output", output[:0], len(output))
	}

	key := make([]byte, 32)
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			output := make([]byte, size.N)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				prf(key, output)
			}
		})
	}
}

func BenchmarkSchemeStream(b *testing.B) {
	stream := func(key, nonce, message []byte) []byte {
		protocol := thyrse.New("stream")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		return protocol.Mask("message", message[:0], message)
	}

	key := make([]byte, 32)
	nonce := make([]byte, 16)
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			output := make([]byte, size.N)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				stream(key, nonce, output)
			}
		})
	}
}

func BenchmarkSchemeAEAD(b *testing.B) {
	aead := func(key, nonce, ad, message []byte) []byte {
		protocol := thyrse.New("aead")
		protocol.Mix("key", key)
		protocol.Mix("nonce", nonce)
		protocol.Mix("ad", ad)
		return protocol.Seal("message", message[:0], message)
	}

	key := make([]byte, 32)
	nonce := make([]byte, 16)
	ad := make([]byte, 32)
	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			output := make([]byte, size.N+thyrse.TagSize)
			b.ReportAllocs()
			b.SetBytes(int64(len(output)))
			for b.Loop() {
				aead(key, nonce, ad, output[:size.N])
			}
		})
	}
}
