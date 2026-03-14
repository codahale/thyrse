package keccak

import "testing"

func TestProcessLeavesKT128(t *testing.T) {
	const blockSize = 8192

	// Build deterministic input: 8 × 8192 bytes.
	input := make([]byte, 8*blockSize)
	for i := range input {
		input[i] = byte(i*7 + i>>8)
	}

	// Compute expected state via generic path.
	var want State8
	processLeavesKT128Generic(input, &want)

	// Compute state via arch-dispatched path.
	var got State8
	ProcessLeavesKT128(input, &got)

	for lane := range 25 {
		for inst := range 8 {
			if got.a[lane][inst] != want.a[lane][inst] {
				t.Errorf("lane %d, inst %d: got %016x, want %016x",
					lane, inst, got.a[lane][inst], want.a[lane][inst])
			}
		}
	}
}

func BenchmarkProcessLeavesKT128(b *testing.B) {
	const blockSize = 8192
	input := make([]byte, 8*blockSize)
	for i := range input {
		input[i] = byte(i)
	}
	var s State8
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		ProcessLeavesKT128(input, &s)
	}
}
