//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600AVX512(a *State1)

//go:noescape
func p1600x8Lane(a *State8)

//go:noescape
func p1600x8AVX512State(a *State8)

func permute12x1Arch(s *State1) bool {
	if hasAVX512 {
		p1600AVX512(s)
	} else {
		p1600(s)
	}
	return true
}

func permute12x2Arch(s *State2) bool {
	if hasAVX512 {
		// Instance-major layout: each half is a contiguous State1.
		p1600AVX512((*State1)(unsafe.Pointer(&s.a[0])))
		p1600AVX512((*State1)(unsafe.Pointer(&s.a[1])))
	} else {
		// Back x2 permutation with x8: scatter into State8, permute, gather.
		var s8 State8
		for i := range Lanes {
			s8.a[i][0] = s.lane2val(i, 0)
			s8.a[i][1] = s.lane2val(i, 1)
		}
		permute12x8Arch(&s8)
		for i := range Lanes {
			*s.lane2(i, 0) = s8.a[i][0]
			*s.lane2(i, 1) = s8.a[i][1]
		}
	}
	return true
}

func permute12x4Arch(s *State4) bool {
	// Back x4 permutation with x8: pad State4 into State8, permute, extract.
	var s8 State8
	for i := range Lanes {
		s8.a[i][0] = s.a[i][0]
		s8.a[i][1] = s.a[i][1]
		s8.a[i][2] = s.a[i][2]
		s8.a[i][3] = s.a[i][3]
	}
	permute12x8Arch(&s8)
	for i := range Lanes {
		s.a[i][0] = s8.a[i][0]
		s.a[i][1] = s8.a[i][1]
		s.a[i][2] = s8.a[i][2]
		s.a[i][3] = s8.a[i][3]
	}
	return true
}

func permute12x8Arch(s *State8) bool {
	if hasAVX512 {
		p1600x8AVX512State(s)
	} else {
		p1600x8Lane(s)
	}
	return true
}

const AvailableLanes = 8
