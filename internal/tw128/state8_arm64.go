//go:build arm64 && !purego

package tw128

//go:noescape
func p1600x8Lane(a *state8)

func permute12x8Arch(s *state8) bool {
	p1600x8Lane(s)
	return true
}
