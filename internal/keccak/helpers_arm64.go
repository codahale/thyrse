//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func fastLoopAbsorb168x1(s *State1, in *byte, n int)

//go:noescape
func fastLoopAbsorb168x2(s *State2, in0, in1 *byte, n int)

//go:noescape
func fastLoopAbsorb168x4(s *State4, in0, in1, in2, in3 *byte, n int)

//go:noescape
func fastLoopAbsorb168x8(s *State8, in0, in1, in2, in3, in4, in5, in6, in7 *byte, n int)

func fastLoopAbsorb168x1Arch(s *State1, in []byte) bool {
	if !useArchPermute1 {
		return false
	}
	fastLoopAbsorb168x1(s, unsafe.SliceData(in), len(in))
	return true
}

func fastLoopAbsorb168x2Arch(s *State2, in0, in1 []byte) bool {
	if selectedP2 != permute2ARM64Lane {
		return false
	}
	fastLoopAbsorb168x2(s, unsafe.SliceData(in0), unsafe.SliceData(in1), len(in0))
	return true
}

func fastLoopAbsorb168x4Arch(s *State4, in0, in1, in2, in3 []byte) bool {
	if selectedP4 != permute4ARM64Lane {
		return false
	}
	fastLoopAbsorb168x4(s, unsafe.SliceData(in0), unsafe.SliceData(in1),
		unsafe.SliceData(in2), unsafe.SliceData(in3), len(in0))
	return true
}

func fastLoopAbsorb168x8Arch(s *State8, in0, in1, in2, in3, in4, in5, in6, in7 []byte) bool {
	if selectedP8 != permute8ARM64Lane {
		return false
	}
	fastLoopAbsorb168x8(s, unsafe.SliceData(in0), unsafe.SliceData(in1),
		unsafe.SliceData(in2), unsafe.SliceData(in3),
		unsafe.SliceData(in4), unsafe.SliceData(in5),
		unsafe.SliceData(in6), unsafe.SliceData(in7), len(in0))
	return true
}
