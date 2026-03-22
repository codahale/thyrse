//go:build !amd64 || purego || thyrse_disable_avx512

package cpuid

var HasAVX512 = false
