//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func fastLoopAbsorb168x8AVX512(s *State8, in *byte, stride, n int)

func fastLoopAbsorb168x1Arch(_ *State1, _ []byte) bool { return false }

func fastLoopAbsorb168x2Arch(_ *State2, _ []byte, _, _ int) bool { return false }

func fastLoopAbsorb168x4Arch(_ *State4, _ []byte, _, _ int) bool { return false }

func fastLoopAbsorb168x8Arch(s *State8, in []byte, stride, n int) bool {
	if selectedP8 != permute8AMD64AVX512State {
		return false
	}
	fastLoopAbsorb168x8AVX512(s, unsafe.SliceData(in), stride, n)
	return true
}
