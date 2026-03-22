//go:build (!amd64 && !arm64) || purego

package tw128

func permute12x1Arch(_ *duplex) bool { return false }
