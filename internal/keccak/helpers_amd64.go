//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x2(s *State2, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x4(s *State4, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x8AVX2(s *State8, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x8AVX512(s *State8, in *byte, stride, n int)

func fastLoopAbsorb168x1Arch(s *State1, in []byte) bool {
	fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	return true
}

func fastLoopAbsorb168x2Arch(s *State2, in []byte, stride, n int) bool {
	fastLoopAbsorb168x2(s, unsafe.SliceData(in), stride, n)
	return true
}

func fastLoopAbsorb168x4Arch(s *State4, in []byte, stride, n int) bool {
	fastLoopAbsorb168x4(s, unsafe.SliceData(in), stride, n)
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
func fastLoopEncrypt167x1(s *State1, src, dst *byte, n int, padWord uint64)

//go:noescape
func fastLoopDecrypt167x1(s *State1, src, dst *byte, n int, padWord uint64)

//go:noescape
func fastLoopEncrypt167x2(s *State2, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopDecrypt167x2(s *State2, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopEncrypt167x4(s *State4, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopDecrypt167x4(s *State4, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopEncrypt167x8AVX2(s *State8, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopDecrypt167x8AVX2(s *State8, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopEncrypt167x8AVX512(s *State8, src, dst *byte, stride, n int, padWord uint64)

//go:noescape
func fastLoopDecrypt167x8AVX512(s *State8, src, dst *byte, stride, n int, padWord uint64)

func fastLoopEncrypt167x1Arch(s *State1, src, dst []byte, padWord uint64) bool {
	fastLoopEncrypt167x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src), padWord)
	return true
}

func fastLoopDecrypt167x1Arch(s *State1, src, dst []byte, padWord uint64) bool {
	fastLoopDecrypt167x1(s, unsafe.SliceData(src), unsafe.SliceData(dst), len(src), padWord)
	return true
}

func fastLoopEncrypt167x2Arch(s *State2, src, dst []byte, stride, n int, padWord uint64) bool {
	fastLoopEncrypt167x2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	return true
}

func fastLoopDecrypt167x2Arch(s *State2, src, dst []byte, stride, n int, padWord uint64) bool {
	fastLoopDecrypt167x2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	return true
}

func fastLoopEncrypt167x4Arch(s *State4, src, dst []byte, stride, n int, padWord uint64) bool {
	fastLoopEncrypt167x4(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	return true
}

func fastLoopDecrypt167x4Arch(s *State4, src, dst []byte, stride, n int, padWord uint64) bool {
	fastLoopDecrypt167x4(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	return true
}

func fastLoopEncrypt167x8Arch(s *State8, src, dst []byte, stride, n int, padWord uint64) bool {
	if hasAVX512 {
		fastLoopEncrypt167x8AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	} else {
		fastLoopEncrypt167x8AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	}
	return true
}

func fastLoopDecrypt167x8Arch(s *State8, src, dst []byte, stride, n int, padWord uint64) bool {
	if hasAVX512 {
		fastLoopDecrypt167x8AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	} else {
		fastLoopDecrypt167x8AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n, padWord)
	}
	return true
}
