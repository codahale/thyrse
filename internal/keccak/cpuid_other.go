//go:build !amd64 || purego || thyrse_disable_avx512

package keccak

var hasAVX512 = false
var _ = hasAVX512
