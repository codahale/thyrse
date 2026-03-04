//go:build arm64

package keccak

import "github.com/klauspost/cpuid/v2"

func archBackend() (backend, bool) {
	if cpuid.CPU.Has(cpuid.SHA3) {
		return backendARM64SHA3, true
	}
	return backendGeneric, true
}
