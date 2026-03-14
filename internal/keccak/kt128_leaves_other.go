//go:build (!amd64 && !arm64) || purego

package keccak

func processLeavesKT128Arch(_ []byte, _ *[256]byte) bool { return false }
