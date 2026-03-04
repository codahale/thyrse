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
	if !useArchPermute1 {
		return false
	}
	fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	return true
}

func fastLoopAbsorb168x2Arch(s *State2, in []byte, stride, n int) bool {
	if selectedP2 != permute2ARM64Lane {
		return false
	}
	fastLoopAbsorb168x2(s, unsafe.SliceData(in), stride, n)
	return true
}

func fastLoopAbsorb168x4Arch(s *State4, in []byte, stride, n int) bool {
	if selectedP4 != permute4ARM64Lane {
		return false
	}
	fastLoopAbsorb168x4(s, unsafe.SliceData(in), stride, n)
	return true
}

func fastLoopAbsorb168x8Arch(s *State8, in []byte, stride, n int) bool {
	if selectedP8 != permute8ARM64Lane {
		return false
	}
	fastLoopAbsorb168x8(s, unsafe.SliceData(in), stride, n)
	return true
}
