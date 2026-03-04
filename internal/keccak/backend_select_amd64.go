//go:build amd64

package keccak

import "github.com/klauspost/cpuid/v2"

func archBackend() (backend, bool) {
	switch {
	case cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL):
		return backendAMD64AVX512, true
	case cpuid.CPU.Has(cpuid.AVX2):
		return backendAMD64AVX2, true
	case cpuid.CPU.Has(cpuid.SSE2):
		return backendAMD64SSE2, true
	default:
		return backendGeneric, true
	}
}
