//go:build amd64 && !purego

package mem

// XORAndReplace sets dst[i] = src[i] ^ state[i] and state[i] = src[i] for each i.
//
//go:noescape
func XORAndReplace(dst, src, state []byte)
