//go:build (!amd64 && !arm64) || purego

package keccak

func permute12x1Arch(_ *State1) bool { return false }

func permute12x2Arch(_ *State2) bool { return false }

func permute12x4Arch(_ *State4) bool { return false }

func permute12x8Arch(_ *State8) bool { return false }

func fastLoopAbsorb168x1Arch(_ *State1, _ []byte) bool { return false }

func fastLoopAbsorb168x2Arch(_ *State2, _ []byte, _, _ int) bool { return false }

func fastLoopAbsorb168x4Arch(_ *State4, _ []byte, _, _ int) bool { return false }

func fastLoopAbsorb168x8Arch(_ *State8, _ []byte, _, _ int) bool { return false }

func fastLoopEncrypt167x1Arch(_ *State1, _, _ []byte, _ uint64) bool { return false }

func fastLoopDecrypt167x1Arch(_ *State1, _, _ []byte, _ uint64) bool { return false }

func fastLoopEncrypt167x2Arch(_ *State2, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x2Arch(_ *State2, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopEncrypt167x4Arch(_ *State4, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x4Arch(_ *State4, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopEncrypt167x8Arch(_ *State8, _, _ []byte, _ int, _ int, _ uint64) bool { return false }

func fastLoopDecrypt167x8Arch(_ *State8, _, _ []byte, _ int, _ int, _ uint64) bool { return false }
