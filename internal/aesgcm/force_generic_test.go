//go:build (amd64 || arm64) && !purego

package aesgcm

import "testing"

// TestGenericFallback forces the portable path on hardware that has the AES-GCM
// extensions, validating the fallback against the same stdlib oracle. It mutates
// the package-level supportsGCM flag, so it must not run in parallel with other
// tests.
func TestGenericFallback(t *testing.T) {
	if !supportsGCM {
		t.Skip("no hardware AES-GCM; generic path is already the default")
	}
	supportsGCM = false
	t.Cleanup(func() { supportsGCM = true })

	key := fill(KeySize, 1)
	nonce := fill(NonceSize, 2)
	for _, n := range testSizes {
		checkOneShot(t, key, nonce, fill(n, int64(n)))
	}
	// Non-standard nonce exercises GHASH-based counter derivation on the
	// generic path as well.
	checkOneShot(t, key, fill(8, 99), fill(200, 6))
}
