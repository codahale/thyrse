//go:build amd64 && !purego

package keccak

import "unsafe"

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

//go:noescape
func fastLoopAbsorb168x8AVX2(s *State8, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x8AVX512(s *State8, in *byte, stride, n int)

func fastLoopAbsorb168x8Arch(s *State8, in []byte, stride, n int) bool {
	if hasAVX512 {
		fastLoopAbsorb168x8AVX512(s, unsafe.SliceData(in), stride, n)
	} else {
		fastLoopAbsorb168x8AVX2(s, unsafe.SliceData(in), stride, n)
	}
	return true
}

//go:noescape
func fastLoopEncrypt168x8AVX2(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopDecrypt168x8AVX2(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopEncrypt168x8AVX512(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopDecrypt168x8AVX512(s *State8, src, dst *byte, stride, n int)

func fastLoopEncrypt168x8Arch(s *State8, src, dst []byte, stride, n int) bool {
	if hasAVX512 {
		fastLoopEncrypt168x8AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	} else {
		fastLoopEncrypt168x8AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	}
	return true
}

func fastLoopDecrypt168x8Arch(s *State8, src, dst []byte, stride, n int) bool {
	if hasAVX512 {
		fastLoopDecrypt168x8AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	} else {
		fastLoopDecrypt168x8AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	}
	return true
}
