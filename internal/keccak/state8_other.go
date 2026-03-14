//go:build (!amd64 && !arm64) || purego

package keccak

const AvailableLanes = 1

func permute12x8Arch(_ *State8) bool { return false }

