//go:build arm64 && !purego

package kt128

import "unsafe"

//go:noescape
func p1600(a *sponge)

func permute12x1Arch(s *sponge) bool {
	p1600(s)
	return true
}

//go:noescape
func fastLoopAbsorb168x1(s *sponge, in *byte, n int)

func fastLoopAbsorb168x1Arch(s *sponge, in []byte) bool {
	fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	return true
}

//go:noescape
func p1600x2Lane(a *[lanes][2]uint64)
