//go:build (!amd64 && !arm64) || purego

package kt128

func permute12x1Arch(_ *sponge) bool { return false }

func fastLoopAbsorb168x1Arch(_ *sponge, _ []byte) bool { return false }
