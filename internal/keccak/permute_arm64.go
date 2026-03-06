//go:build arm64 && !purego

package keccak

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600x2Lane(a *State2)

//go:noescape
func p1600x4Lane(a *State4)

//go:noescape
func p1600x8Lane(a *State8)

func permute12x1Arch(s *State1) bool {
	p1600(s)
	return true
}

func permute12x2Arch(s *State2) bool {
	p1600x2Lane(s)
	return true
}

func permute12x4Arch(s *State4) bool {
	p1600x4Lane(s)
	return true
}

func permute12x8Arch(s *State8) bool {
	p1600x8Lane(s)
	return true
}

const AvailableLanes = 4
