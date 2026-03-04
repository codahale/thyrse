//go:build !keccak_generic && !keccak_amd64_sse2 && !keccak_amd64_avx2 && !keccak_amd64_avx512 && !keccak_arm64_sha3

package keccak

const forcedBackend = ""
