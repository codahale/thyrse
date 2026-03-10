//go:build (!amd64 && !arm64) || purego

package keccak

const AvailableLanes = 1

func permute12x1Arch(_ *State1) bool { return false }

func permute12x2Arch(_ *State2) bool { return false }

func permute12x8Arch(_ *State8) bool { return false }

func fastLoopAbsorb168x1Arch(_ *State1, _ []byte) bool { return false }

func fastLoopAbsorb168x2Arch(_ *State2, _ []byte, _, _ int) bool { return false }

func fastLoopAbsorb168x8Arch(_ *State8, _ []byte, _, _ int) bool { return false }

func fastLoopEncrypt168x1Arch(_ *State1, _, _ []byte) bool { return false }

func fastLoopDecrypt168x1Arch(_ *State1, _, _ []byte) bool { return false }

func fastLoopEncrypt168x2Arch(_ *State2, _, _ []byte, _, _ int) bool { return false }

func fastLoopDecrypt168x2Arch(_ *State2, _, _ []byte, _, _ int) bool { return false }

func fastLoopEncrypt168x8Arch(_ *State8, _, _ []byte, _, _ int) bool { return false }

func fastLoopDecrypt168x8Arch(_ *State8, _, _ []byte, _, _ int) bool { return false }
