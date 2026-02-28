//go:build (!amd64 && !arm64) || purego

package mem

// XORAndCopy sets dst[i] = a[i] ^ b[i] and b[i] = dst[i] for each i.
func XORAndCopy(dst, a, b []byte) {
	for i := range dst {
		d := a[i] ^ b[i]
		dst[i] = d
		b[i] = d
	}
}
