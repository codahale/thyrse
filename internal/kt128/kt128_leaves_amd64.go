//go:build amd64 && !purego

package kt128

import (
	"unsafe"

	"github.com/codahale/thyrse/internal/cpuid"
)

const availableLanes = 8

//go:noescape
func processLeavesKT128AVX512(input *byte, cvs *byte)

//go:noescape
func processLeavesKT128AVX2(input *byte, cvs *byte)

func processLeavesArch(input []byte, cvs *[256]byte) bool {
	if cpuid.HasAVX512 {
		processLeavesKT128AVX512(unsafe.SliceData(input), &cvs[0])
	} else {
		processLeavesKT128AVX2(unsafe.SliceData(input), &cvs[0])
	}
	return true
}
