//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func processLeavesKT128ARM64(input *byte, cvs *byte)

func processLeavesKT128Arch(input []byte, cvs *[256]byte) bool {
	processLeavesKT128ARM64(unsafe.SliceData(input), &cvs[0])
	return true
}
