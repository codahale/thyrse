//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func processLeavesKT128ARM64(input *byte, s *State8)

func processLeavesKT128Arch(input []byte, s *State8) bool {
	processLeavesKT128ARM64(unsafe.SliceData(input), s)
	return true
}
