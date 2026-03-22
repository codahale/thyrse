//go:build (!amd64 && !arm64) || purego

package kt128

const availableLanes = 1

func processLeavesArch(_ []byte, _ *[256]byte) bool { return false }
