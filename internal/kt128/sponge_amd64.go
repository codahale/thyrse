//go:build amd64 && !purego

package kt128

import (
	"unsafe"

	"github.com/codahale/thyrse/internal/cpuid"
)

//go:noescape
func p1600(a *sponge)

//go:noescape
func p1600AVX512(a *sponge)

func permute12x1Arch(s *sponge) bool {
	if cpuid.HasAVX512 {
		p1600AVX512(s)
	} else {
		p1600(s)
	}
	return true
}

//go:noescape
func fastLoopAbsorb168x1(s *sponge, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x1AVX512(s *sponge, in *byte, n int)

func fastLoopAbsorb168x1Arch(s *sponge, in []byte) bool {
	if cpuid.HasAVX512 {
		fastLoopAbsorb168x1AVX512(s, unsafe.SliceData(in), len(in))
	} else {
		fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	}
	return true
}
