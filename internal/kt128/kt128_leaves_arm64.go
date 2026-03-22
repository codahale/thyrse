//go:build arm64 && !purego

package kt128

import "unsafe"

const availableLanes = 8

//go:noescape
func processLeavesARM64(input *byte, cvs *byte)

func processLeavesArch(input []byte, cvs *[256]byte) bool {
	processLeavesARM64(unsafe.SliceData(input), &cvs[0])
	return true
}
