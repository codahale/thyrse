//go:build (!amd64 && !arm64) || purego

package tw128

func encryptChunksArch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }

func decryptChunksArch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }
