//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func processLeavesKT128AVX512(input *byte, s *State8)

//go:noescape
func processLeavesKT128AVX2(input *byte, s *State8)

func processLeavesKT128Arch(input []byte, s *State8) bool {
	if hasAVX512 {
		processLeavesKT128AVX512(unsafe.SliceData(input), s)
	} else {
		processLeavesKT128AVX2(unsafe.SliceData(input), s)
	}
	return true
}
