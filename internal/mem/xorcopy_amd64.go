//go:build amd64 && !purego

package mem

// XORAndCopy sets dst[i] = a[i] ^ b[i] and b[i] = dst[i] for each i.
//
//go:noescape
func XORAndCopy(dst, a, b []byte)
