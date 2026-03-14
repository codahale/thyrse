//go:build (!amd64 && !arm64) || purego

package keccak

func encryptChunksTW128Arch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }

func decryptChunksTW128Arch(_ *state8, _, _ []byte, _ *[256]byte) bool { return false }
