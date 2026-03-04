//go:build arm64

package keccak

import "github.com/klauspost/cpuid/v2"

func archBackend() (backend, bool) {
	if cpuid.CPU.Has(cpuid.SHA3) {
		return backendByName("arm64_sha3"), true
	}
	return newGenericBackend(), true
}
