//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func p1600x8Lane(a *State8)

func permute12x8Arch(s *State8) bool {
	p1600x8Lane(s)
	return true
}

const AvailableLanes = 8

func fastLoopAbsorb168x8Arch(_ *State8, _ []byte, _, _ int) bool { return false }

//go:noescape
func fastLoopEncrypt168x8(s *State8, src, dst *byte, stride, n int)

//go:noescape
func fastLoopDecrypt168x8(s *State8, src, dst *byte, stride, n int)

func fastLoopEncrypt168x8Arch(s *State8, src, dst []byte, stride, n int) bool {
	fastLoopEncrypt168x8(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	return true
}

func fastLoopDecrypt168x8Arch(s *State8, src, dst []byte, stride, n int) bool {
	fastLoopDecrypt168x8(s, unsafe.SliceData(src), unsafe.SliceData(dst), stride, n)
	return true
}
