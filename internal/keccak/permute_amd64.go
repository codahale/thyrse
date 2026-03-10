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
		p1600AVX512((*State1)(unsafe.Pointer(&s.a[0])))
		p1600AVX512((*State1)(unsafe.Pointer(&s.a[1])))
	} else {
		p1600((*State1)(unsafe.Pointer(&s.a[0])))
		p1600((*State1)(unsafe.Pointer(&s.a[1])))
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
