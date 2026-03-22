//go:build amd64 && !purego

package tw128

import (
	"unsafe"

	"github.com/codahale/thyrse/internal/cpuid"
)

//go:noescape
func encryptChunksAVX512(s *state8, src, dst *byte, tags *byte)

//go:noescape
func encryptChunksBodyAVX2(s *state8, src, dst *byte)

//go:noescape
func decryptChunksAVX512(s *state8, src, dst *byte, tags *byte)

//go:noescape
func decryptChunksBodyAVX2(s *state8, src, dst *byte)

func encryptChunksArch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		encryptChunksAVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	} else {
		encryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
		finishEncryptChunks(s, src, dst, tags)
	}
	return true
}

func decryptChunksArch(s *state8, src, dst []byte, tags *[256]byte) bool {
	if cpuid.HasAVX512 {
		decryptChunksAVX512(s, unsafe.SliceData(src), unsafe.SliceData(dst), &tags[0])
	} else {
		decryptChunksBodyAVX2(s, unsafe.SliceData(src), unsafe.SliceData(dst))
		finishDecryptChunks(s, src, dst, tags)
	}
	return true
}
