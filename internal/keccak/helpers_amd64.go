//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x1AVX512(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x8AVX2(s *State8, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x8AVX512(s *State8, in *byte, stride, n int)

func fastLoopAbsorb168x1Arch(s *State1, in []byte) bool {
	if hasAVX512 {
		fastLoopAbsorb168x1AVX512(s, unsafe.SliceData(in), len(in))
	} else {
		fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	}
	return true
}

func fastLoopAbsorb168x8Arch(s *State8, in []byte, stride, n int) bool {
	if hasAVX512 {
		fastLoopAbsorb168x8AVX512(s, unsafe.SliceData(in), stride, n)
	} else {
		fastLoopAbsorb168x8AVX2(s, unsafe.SliceData(in), stride, n)
	}
	return true
}

//go:noescape
func fastLoopEncrypt168x1(s *State1, src, dst *byte, n int)

//go:noescape
func fastLoopDecrypt168x1(s *State1, src, dst *byte, n int)

//go:noescape
func fastLoopEncrypt168x8AVX2(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopDecrypt168x8AVX2(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopEncrypt168x8AVX512(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopDecrypt168x8AVX512(s *State8, src, dst *byte, stride, n int)

func fastLoopEncrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopEncrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}

func fastLoopDecrypt168x1Arch(s *State1, src, dst []byte) bool {
	fastLoopDecrypt168x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src))
	return true
}

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
