//go:build amd64 && !purego

package keccak

//go:noescape
func p1600x8Lane(a *State8)

//go:noescape
func p1600x8AVX512State(a *State8)

func permute12x8Arch(s *State8) bool {
	if hasAVX512 {
		p1600x8AVX512State(s)
	} else {
		p1600x8Lane(s)
	}
	return true
}

const AvailableLanes = 8
