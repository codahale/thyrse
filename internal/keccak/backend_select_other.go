//go:build !amd64 && !arm64

package keccak

func archBackend() (backend, bool) {
	return backendGeneric, false
}
