//go:build (!amd64 && !arm64) || purego

package mem

// XORInPlace sets dst[i] ^= src[i] for each i.
func XORInPlace(dst, src []byte) {
	for i, s := range src[:len(dst)] {
		dst[i] ^= s
	}
}
