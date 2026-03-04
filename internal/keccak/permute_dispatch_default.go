//go:build (!amd64 && !arm64) || purego

package keccak

func permute12x1Arch(_ *State1) bool { return false }

func permute12x2Arch(_ *State2) bool { return false }

func permute12x4Arch(_ *State4) bool { return false }

func permute12x8Arch(_ *State8) bool { return false }
