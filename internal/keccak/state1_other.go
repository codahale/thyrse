//go:build (!amd64 && !arm64) || purego

package keccak

func permute12x1Arch(_ *State1) bool { return false }

func fastLoopAbsorb168x1Arch(_ *State1, _ []byte) bool { return false }

func fastLoopEncrypt168x1Arch(_ *State1, _, _ []byte) bool { return false }

func fastLoopDecrypt168x1Arch(_ *State1, _, _ []byte) bool { return false }
