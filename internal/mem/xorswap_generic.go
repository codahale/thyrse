//go:build (!amd64 && !arm64) || purego

package mem

// XORAndReplace sets dst[i] = src[i] ^ state[i] and state[i] = src[i] for each i.
func XORAndReplace(dst, src, state []byte) {
	for i, c := range src[:len(dst)] {
		dst[i] = c ^ state[i]
		state[i] = c
	}
}
