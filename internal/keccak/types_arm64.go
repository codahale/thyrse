//go:build arm64 && !purego

package keccak

// State2 is a pair of Keccak-p[1600] states in lane-major layout.
// ARM64 NEON uses lane-major for 128-bit vector packing.
type State2 struct {
	a [Lanes][2]uint64
}

func (s *State2) lane2(lane, inst int) *uint64   { return &s.a[lane][inst] }
func (s *State2) lane2val(lane, inst int) uint64  { return s.a[lane][inst] }
