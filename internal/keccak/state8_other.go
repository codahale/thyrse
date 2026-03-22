//go:build (!amd64 && !arm64) || purego

package keccak

func permute12x8Arch(_ *state8) bool { return false }
