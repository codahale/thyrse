//go:build (!amd64 && !arm64) || purego

package keccak

func processLeavesKT128Arch(_ []byte, _ *State8) bool { return false }
