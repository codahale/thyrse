//go:build arm64 && !purego

package mem

// XORAndCopy sets dst[i] = a[i] ^ b[i] and b[i] = dst[i] for each i.
//
//go:noescape
//goland:noinspection GoUnusedParameter
func XORAndCopy(dst, a, b []byte)
