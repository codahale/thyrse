// Package keccak provides an optimized implementation of the Keccak-f[1600,12] permutation.
package keccak

// Lanes is the number of permutations the host machine can perform in parallel.
var Lanes = 1

// P1600 applies the Keccak-p[1600, 12] permutation to the state.
func P1600(state *[200]byte) {
	p1600(state)
}
