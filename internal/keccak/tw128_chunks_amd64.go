//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func encryptChunksTW128AVX512(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func encryptChunksTW128AVX2(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func decryptChunksTW128AVX512(s *state8, src, dst *byte, cvs *byte)

//go:noescape
func decryptChunksTW128AVX2(s *state8, src, dst *byte, cvs *byte)

func encryptChunksTW128Arch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	if hasAVX512 {
		encryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	} else {
		encryptChunksTW128AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	}
	return true
}

func decryptChunksTW128Arch(s *state8, src, dst []byte, cvs *[256]byte) bool {
	if hasAVX512 {
		decryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	} else {
		decryptChunksTW128AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst), &cvs[0])
	}
	return true
}
