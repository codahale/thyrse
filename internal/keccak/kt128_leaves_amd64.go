//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func processLeavesKT128AVX512(input *byte, cvs *byte)

//go:noescape
func processLeavesKT128AVX2(input *byte, cvs *byte)

func processLeavesKT128Arch(input []byte, cvs *[256]byte) bool {
	if hasAVX512 {
		processLeavesKT128AVX512(unsafe.SliceData(input), &cvs[0])
	} else {
		processLeavesKT128AVX2(unsafe.SliceData(input), &cvs[0])
	}
	return true
}
