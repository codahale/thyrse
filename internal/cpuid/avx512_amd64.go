//go:build amd64 && !purego && !thyrse_disable_avx512

package cpuid

func hasAVX512VL() bool

var HasAVX512 = hasAVX512VL()
