package digest_test

import (
	"testing"

	"github.com/codahale/thyrse/internal/testdata"
	"github.com/codahale/thyrse/schemes/basic/digest"
)

func BenchmarkDigest(b *testing.B) {
	h := digest.New("com.example.benchmark")

	for _, size := range testdata.Sizes {
		b.Run(size.Name, func(b *testing.B) {
			input := make([]byte, size.N)
			dst := make([]byte, 32)

			b.ReportAllocs()
			b.SetBytes(int64(size.N))
			for b.Loop() {
				h.Reset()
				h.Write(input)
				h.Sum(dst[:0])
			}
		})
	}
}
