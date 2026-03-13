//go:build arm64 && !purego

package keccak

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600x8Lane(a *State8)

func permute12x1Arch(s *State1) bool {
	p1600(s)
	return true
}

func permute12x8Arch(s *State8) bool {
	p1600x8Lane(s)
	return true
}

const AvailableLanes = 8
