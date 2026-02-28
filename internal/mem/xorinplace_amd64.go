//go:build amd64 && !purego

package mem

// XORInPlace sets dst[i] ^= src[i] for each i.
//
//go:noescape
func XORInPlace(dst, src []byte)
