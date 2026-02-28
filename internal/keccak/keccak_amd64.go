// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package keccak

import (
	"github.com/klauspost/cpuid/v2"
)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600(a *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600x2AVX512(a, b *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600x2SSE2(a, b *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600x4AVX512(a, b, c, d *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600x4AVX2(a, b, c, d *[200]byte)

// P1600x2 applies the Keccak-p[1600, 12] permutation in parallel to the two states.
//
// Uses runtime CPU feature detection to choose between a 2x AVX-512 implementation, a 2x SS2 implementation, and a pure
// Go implementation.
func P1600x2(state1, state2 *[200]byte) {
	if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
		p1600x2AVX512(state1, state2)
	} else if cpuid.CPU.Has(cpuid.SSE2) {
		p1600x2SSE2(state1, state2)
	} else {
		f1600Generic(state1, 12)
		f1600Generic(state2, 12)
	}
}

// P1600x4 applies the Keccak-p[1600, 12] permutation in parallel to the four states.
//
// Uses runtime CPU feature detection to choose between a 4x AVX-512 implementation, a 4x AVX2 implementation, a 2x SS2
// implementation, and a pure Go implementation.
func P1600x4(state1, state2, state3, state4 *[200]byte) {
	if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
		p1600x4AVX512(state1, state2, state3, state4)
	} else if cpuid.CPU.Has(cpuid.AVX2) {
		p1600x4AVX2(state1, state2, state3, state4)
	} else if cpuid.CPU.Has(cpuid.SSE2) {
		p1600x2SSE2(state1, state2)
		p1600x2SSE2(state3, state4)
	} else {
		f1600Generic(state1, 12)
		f1600Generic(state2, 12)
		f1600Generic(state3, 12)
		f1600Generic(state4, 12)
	}
}

func init() {
	if cpuid.CPU.Has(cpuid.AVX512F) && cpuid.CPU.Has(cpuid.AVX512VL) {
		Lanes = 4
	} else if cpuid.CPU.Has(cpuid.AVX2) {
		Lanes = 4
	}
	Lanes = 2
}
