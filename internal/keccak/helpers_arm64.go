//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x2(s *State2, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x4(s *State4, in *byte, stride, n int)

//go:noescape
func fastLoopAbsorb168x8(s *State8, in *byte, stride, n int)

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
	fastLoopAbsorb168x8(s, unsafe.SliceData(in), stride, n)
	return true
}

func fastLoopEncrypt167x1Arch(_ *State1, _, _ []byte, _ uint64) bool { return false }

func fastLoopDecrypt167x1Arch(_ *State1, _, _ []byte, _ uint64) bool { return false }

func fastLoopEncrypt167x2Arch(_ *State2, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x2Arch(_ *State2, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopEncrypt167x4Arch(_ *State4, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x4Arch(_ *State4, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopEncrypt167x8Arch(_ *State8, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x8Arch(_ *State8, _, _ []byte, _ int, _ int, _ uint64) bool { return false }
