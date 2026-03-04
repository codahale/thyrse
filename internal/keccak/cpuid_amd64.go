//go:build amd64 && !purego && !thyrse_disable_avx512

package keccak

func hasAVX512VL() bool

var hasAVX512 = hasAVX512VL()
