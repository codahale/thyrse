//go:build !arm64 || purego

package keccak

func fastLoopAbsorb168x1Arch(_ *State1, _ []byte) bool { return false }

func fastLoopAbsorb168x2Arch(_ *State2, _, _ []byte) bool { return false }

func fastLoopAbsorb168x4Arch(_ *State4, _, _, _, _ []byte) bool { return false }

func fastLoopAbsorb168x8Arch(_ *State8, _, _, _, _, _, _, _, _ []byte) bool { return false }
