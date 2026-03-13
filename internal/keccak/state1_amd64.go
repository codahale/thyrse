//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func p1600(a *State1)

//go:noescape
func p1600AVX512(a *State1)

func permute12x1Arch(s *State1) bool {
	if hasAVX512 {
		p1600AVX512(s)
	} else {
		p1600(s)
	}
	return true
}

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x1AVX512(s *State1, in *byte, n int)

func fastLoopAbsorb168x1Arch(s *State1, in []byte) bool {
	if hasAVX512 {
		fastLoopAbsorb168x1AVX512(s, unsafe.SliceData(in), len(in))
	} else {
		fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	}
	return true
}

//go:noescape
func fastLoopEncrypt168x1(s *State1, src, dst *byte, n int)

//go:noescape
func fastLoopDecrypt168x1(s *State1, src, dst *byte, n int)

func fastLoopEncrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopEncrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}

func fastLoopDecrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopDecrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}
