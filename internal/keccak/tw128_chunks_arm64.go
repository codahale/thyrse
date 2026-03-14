//go:build arm64 && !purego

package keccak

import "unsafe"

//go:noescape
func encryptChunksTW128ARM64(s *State8, src, dst *byte)

//go:noescape
func decryptChunksTW128ARM64(s *State8, src, dst *byte)

func encryptChunksTW128Arch(s *State8, src, dst []byte) bool {
	encryptChunksTW128ARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	return true
}

func decryptChunksTW128Arch(s *State8, src, dst []byte) bool {
	decryptChunksTW128ARM64(s, unsafe.SliceData(src), unsafe.SliceData(dst))
	return true
}
