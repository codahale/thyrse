//go:build amd64 && !purego

package keccak

import "unsafe"

//go:noescape
func encryptChunksTW128AVX512(s *State8, src, dst *byte)

//go:noescape
func encryptChunksTW128AVX2(s *State8, src, dst *byte)

//go:noescape
func decryptChunksTW128AVX512(s *State8, src, dst *byte)

//go:noescape
func decryptChunksTW128AVX2(s *State8, src, dst *byte)

func encryptChunksTW128Arch(s *State8, src, dst []byte) bool {
	if hasAVX512 {
		encryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		encryptChunksTW128AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	return true
}

func decryptChunksTW128Arch(s *State8, src, dst []byte) bool {
	if hasAVX512 {
		decryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	} else {
		decryptChunksTW128AVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	}
	return true
}
