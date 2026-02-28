// Copyright 2025 The Go Authors. All rights reserved.
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
func p1600x2(a, b *[200]byte)

// P1600x2 applies the Keccak-p[1600, 12] permutation in parallel to the two states.
//
// Uses runtime CPU feature detection to choose between a 2x NEON/FEAT_SHA3 implementation and a pure Go implementation.
func P1600x2(state1, state2 *[200]byte) {
	if cpuid.CPU.Has(cpuid.SHA3) {
		p1600x2(state1, state2)
	} else {
		f1600Generic(state1, 12)
		f1600Generic(state2, 12)
	}
}

// P1600x4 applies the Keccak-p[1600, 12] permutation in parallel to the two states.
//
// Uses runtime CPU feature detection to choose between a 2x NEON/FEAT_SHA3 implementation and a pure Go implementation.
func P1600x4(state1, state2, state3, state4 *[200]byte) {
	p1600x2(state1, state2)
	p1600x2(state3, state4)
}

func init() {
	if cpuid.CPU.Has(cpuid.SHA3) {
		Lanes = 2
	} else {
		Lanes = 1
	}
}
