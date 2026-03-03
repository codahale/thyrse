//go:build amd64 && !purego && !avx2 && !sse2 && !avx512

package legacykeccak

import (
	"bytes"
	"crypto/sha3"
	"testing"

	"github.com/klauspost/cpuid/v2"
)

func TestAMD64BackendsP1600x2(t *testing.T) {
	testPermute2 := func(t *testing.T, name string, fn func(a, b *[200]byte)) {
		t.Helper()
		var a, b, aRef, bRef [200]byte

		drbg := sha3.NewSHAKE128()
		_, _ = drbg.Write([]byte("keccak-" + name))
		_, _ = drbg.Read(a[:])
		_, _ = drbg.Read(b[:])
		copy(aRef[:], a[:])
		copy(bRef[:], b[:])

		fn(&a, &b)
		f1600Generic(&aRef, 12)
		f1600Generic(&bRef, 12)

		if !bytes.Equal(a[:], aRef[:]) {
			t.Fatalf("%s state1 mismatch: got %x, want %x", name, a, aRef)
		}
		if !bytes.Equal(b[:], bRef[:]) {
			t.Fatalf("%s state2 mismatch: got %x, want %x", name, b, bRef)
		}
	}

	t.Run("SSE2", func(t *testing.T) {
		if !cpuid.CPU.Has(cpuid.SSE2) {
			t.Skip("SSE2 not supported by host CPU")
		}
		testPermute2(t, "p1600x2SSE2", p1600x2SSE2)
	})

	t.Run("AVX512", func(t *testing.T) {
		if !cpuid.CPU.Has(cpuid.AVX512F) || !cpuid.CPU.Has(cpuid.AVX512VL) {
			t.Skip("AVX-512F/VL not supported by host CPU")
		}
		testPermute2(t, "p1600x2AVX512", p1600x2AVX512)
	})
}

func TestAMD64BackendsP1600x4(t *testing.T) {
	testPermute4 := func(t *testing.T, name string, fn func(a, b, c, d *[200]byte)) {
		t.Helper()
		var a, b, c, d [200]byte
		var aRef, bRef, cRef, dRef [200]byte

		drbg := sha3.NewSHAKE128()
		_, _ = drbg.Write([]byte("keccak-" + name))
		_, _ = drbg.Read(a[:])
		_, _ = drbg.Read(b[:])
		_, _ = drbg.Read(c[:])
		_, _ = drbg.Read(d[:])
		copy(aRef[:], a[:])
		copy(bRef[:], b[:])
		copy(cRef[:], c[:])
		copy(dRef[:], d[:])

		fn(&a, &b, &c, &d)
		f1600Generic(&aRef, 12)
		f1600Generic(&bRef, 12)
		f1600Generic(&cRef, 12)
		f1600Generic(&dRef, 12)

		if !bytes.Equal(a[:], aRef[:]) {
			t.Fatalf("%s state1 mismatch: got %x, want %x", name, a, aRef)
		}
		if !bytes.Equal(b[:], bRef[:]) {
			t.Fatalf("%s state2 mismatch: got %x, want %x", name, b, bRef)
		}
		if !bytes.Equal(c[:], cRef[:]) {
			t.Fatalf("%s state3 mismatch: got %x, want %x", name, c, cRef)
		}
		if !bytes.Equal(d[:], dRef[:]) {
			t.Fatalf("%s state4 mismatch: got %x, want %x", name, d, dRef)
		}
	}

	t.Run("AVX2", func(t *testing.T) {
		if !cpuid.CPU.Has(cpuid.AVX2) {
			t.Skip("AVX2 not supported by host CPU")
		}
		testPermute4(t, "p1600x4AVX2", p1600x4AVX2)
	})

	t.Run("AVX512", func(t *testing.T) {
		if !cpuid.CPU.Has(cpuid.AVX512F) || !cpuid.CPU.Has(cpuid.AVX512VL) {
			t.Skip("AVX-512F/VL not supported by host CPU")
		}
		testPermute4(t, "p1600x4AVX512", p1600x4AVX512)
	})
}
