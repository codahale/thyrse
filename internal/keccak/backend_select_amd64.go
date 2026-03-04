//go:build amd64

package keccak

import "github.com/klauspost/cpuid/v2"

func archBackend() (backend, bool) {
	switch {
	case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
		return backendByName("amd64_avx512"), true
	case cpuid.CPU.Has(cpuid.AVX2):
		return backendByName("amd64_avx2"), true
	case cpuid.CPU.Has(cpuid.SSE2):
		return backendByName("amd64_sse2"), true
	default:
		return newGenericBackend(), true
	}
}
