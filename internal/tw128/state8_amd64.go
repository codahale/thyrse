//go:build amd64 && !purego

package tw128

import "github.com/codahale/thyrse/internal/cpuid"

//go:noescape
func p1600x8Lane(a *state8)

//go:noescape
func p1600x8AVX512State(a *state8)

func permute12x8Arch(s *state8) bool {
	if cpuid.HasAVX512 {
		p1600x8AVX512State(s)
	} else {
		p1600x8Lane(s)
	}
	return true
}
