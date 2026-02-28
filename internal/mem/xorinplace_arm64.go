//go:build arm64 && !purego

package mem

// XORInPlace sets dst[i] ^= src[i] for each i.
//
//go:noescape
//goland:noinspection GoUnusedParameter
func XORInPlace(dst, src []byte)
