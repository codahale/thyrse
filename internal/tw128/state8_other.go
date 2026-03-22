//go:build (!amd64 && !arm64) || purego

package tw128

func permute12x8Arch(_ *state8) bool { return false }
