package aesgcm

import (
	"bytes"
	"testing"
)

// TestNoOverwritePastDst guards against the assembly's full-block final-store
// running past a tightly-sized dst buffer. It places a sentinel region
// immediately after a cap-limited dst and checks the sentinel is untouched, for
// both Encrypt and Decrypt over partial-block inputs.
func TestNoOverwritePastDst(t *testing.T) {
	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	const guard = 32

	for _, n := range []int{1, 5, 15, 17, 31, 33, 100} {
		pt := fill(n, int64(n))

		// Encrypt into a dst of length exactly n, backed by a larger array whose
		// trailing bytes are a sentinel.
		encBacking := make([]byte, n+guard)
		for i := n; i < len(encBacking); i++ {
			encBacking[i] = 0xAA
		}
		ct := encBacking[:n:n] // len and cap exactly n
		Encrypt(ct, key, nonce, pt)
		if !bytes.Equal(encBacking[n:], bytes.Repeat([]byte{0xAA}, guard)) {
			t.Fatalf("Encrypt n=%d overwrote past dst", n)
		}

		// Decrypt into a dst of length exactly n.
		decBacking := make([]byte, n+guard)
		for i := n; i < len(decBacking); i++ {
			decBacking[i] = 0xAA
		}
		ddst := decBacking[:n:n]
		Decrypt(ddst, key, nonce, ct)
		if !bytes.Equal(decBacking[n:], bytes.Repeat([]byte{0xAA}, guard)) {
			t.Fatalf("Decrypt n=%d overwrote past dst", n)
		}
	}
}
