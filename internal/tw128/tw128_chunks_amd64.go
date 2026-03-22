//go:build amd64 && !purego

package tw128

import (
	"unsafe"

	"github.com/codahale/thyrse/internal/cpuid"
)

//go:noescape
func encryptChunksTW128AVX512(s *state8, src, dst *byte, tags *byte)

//go:noescape
func encryptChunksTW128BodyAVX2(s *state8, src, dst *byte)

//go:noescape
func decryptChunksTW128AVX512(s *state8, src, dst *byte, tags *byte)

//go:noescape
func decryptChunksTW128BodyAVX2(s *state8, src, dst *byte)

func encryptChunksTW128Arch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		encryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	} else {
		encryptChunksTW128BodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
		finishEncryptChunksTW128(s, src, dst, tags)
	}
	return true
}

func decryptChunksTW128Arch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		decryptChunksTW128AVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	} else {
		decryptChunksTW128BodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
		finishDecryptChunksTW128(s, src, dst, tags)
	}
	return true
}
