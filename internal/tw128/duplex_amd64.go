//go:build amd64 && !purego

package tw128

import "github.com/codahale/thyrse/internal/cpuid"

//go:noescape
func p1600(a *duplex)

//go:noescape
func p1600AVX512(a *duplex)

func permute12x1Arch(d *duplex) bool {
	if cpuid.HasAVX512 {
		p1600AVX512(d)
	} else {
		p1600(d)
	}
	return true
}
