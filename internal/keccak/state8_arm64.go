//go:build arm64 && !purego

package keccak

//go:noescape
func p1600x8Lane(a *state8)

func permute12x8Arch(s *state8) bool {
	p1600x8Lane(s)
	return true
}

const AvailableLanes = 8
