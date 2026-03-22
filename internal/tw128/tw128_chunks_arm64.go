//go:build arm64 && !purego

package tw128

import "unsafe"

//go:noescape
func encryptChunksARM64(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func decryptChunksARM64(s *state8, src, dst *byte, cvs *byte)

func encryptChunksArch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	encryptChunksARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	return true
}

func decryptChunksArch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	decryptChunksARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	return true
}
