//go:build amd64 && !purego

package keccak

// State2 is a pair of Keccak-p[1600] states in instance-major layout.
// AMD64 uses instance-major so each half is a contiguous State1 for
// zero-copy AVX-512 x1 permutation.
type State2 struct {
	a [2][Lanes]uint64
}

func (s *State2) lane2(lane, inst int) *uint64   { return &s.a[inst][lane] }
func (s *State2) lane2val(lane, inst int) uint64 { return s.a[inst][lane] }
