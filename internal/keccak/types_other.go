//go:build (!amd64 && !arm64) || purego

package keccak

// State2 is a pair of Keccak-p[1600] states in instance-major layout.
type State2 struct {
	a [2][Lanes]uint64
}

func (s *State2) lane2(lane, inst int) *uint64   { return &s.a[inst][lane] }
func (s *State2) lane2val(lane, inst int) uint64 { return s.a[inst][lane] }
