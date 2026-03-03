// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build amd64 && !purego && sse2 && !avx2 && !avx512

package legacykeccak

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600(a *[200]byte)

//go:noescape
//goland:noinspection GoUnusedParameter
func p1600x2SSE2(a, b *[200]byte)

// P1600x2 applies the Keccak-p[1600, 12] permutation in parallel to the two states.
func P1600x2(state1, state2 *[200]byte) {
	p1600x2SSE2(state1, state2)
}

// P1600x4 applies the Keccak-p[1600, 12] permutation in parallel to the four states.
func P1600x4(state1, state2, state3, state4 *[200]byte) {
	p1600x2SSE2(state1, state2)
	p1600x2SSE2(state3, state4)
}

func init() {
	Lanes = 2
}
