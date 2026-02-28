package digest_test

import (
	"testing"

	"github.com/codahale/thyrse/schemes/basic/digest"
)

func BenchmarkDigest(b *testing.B) {
	h := digest.New("com.example.benchmark")

	for _, length := range lengths {
		b.Run(length.name, func(b *testing.B) {
			input := make([]byte, length.n)
			dst := make([]byte, 32)

			b.ReportAllocs()
			b.SetBytes(int64(length.n))
			for b.Loop() {
				h.Reset()
				h.Write(input)
				h.Sum(dst[:0])
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
