//go:build arm64 && !purego

package keccak

import (
	"bytes"
	"crypto/sha3"
	"testing"

	"github.com/klauspost/cpuid/v2"
)

func TestARM64BackendP1600x2(t *testing.T) {
	if !cpuid.CPU.Has(cpuid.SHA3) {
		t.Skip("ARM64 SHA3 extension not supported by host CPU")
	}

	var a, b, aRef, bRef [200]byte

	drbg := sha3.NewSHAKE128()
	_, _ = drbg.Write([]byte("keccak-p1600x2-arm64-sha3"))
	_, _ = drbg.Read(a[:])
	_, _ = drbg.Read(b[:])
	copy(aRef[:], a[:])
	copy(bRef[:], b[:])

	p1600x2(&a, &b)
	f1600Generic(&aRef, 12)
	f1600Generic(&bRef, 12)

	if !bytes.Equal(a[:], aRef[:]) {
		t.Fatalf("p1600x2 state1 mismatch: got %x, want %x", a, aRef)
	}
	if !bytes.Equal(b[:], bRef[:]) {
		t.Fatalf("p1600x2 state2 mismatch: got %x, want %x", b, bRef)
	}
}
