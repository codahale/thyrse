//go:build arm64 && !purego

package tw128

import "unsafe"

//go:noescape
func encryptChunksTW128ARM64(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func decryptChunksTW128ARM64(s *state8, src, dst *byte, cvs *byte)

func encryptChunksTW128Arch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	encryptChunksTW128ARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	return true
}

func decryptChunksTW128Arch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	decryptChunksTW128ARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	return true
}
