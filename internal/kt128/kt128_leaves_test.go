package kt128

import (
	"encoding/binary"
	"testing"
)

func TestProcessLeaves(t *testing.T) {
	const blockSize = 8192

	// Build deterministic input: 8 × 8192 bytes.
	input := make([]byte, 8*blockSize)
	for i := range input {
		input[i] = byte(i*7 + i>>8)
	}

	// Compute expected CVs via generic path.
	var want [256]byte
	processLeavesGeneric(input, &want)

	// Compute CVs via arch-dispatched path.
	var got [256]byte
	processLeaves(input, &got)

	if got != want {
		for inst := range 8 {
			wantCV := want[inst*32 : inst*32+32]
			gotCV := got[inst*32 : inst*32+32]
			for lane := range 4 {
				w := binary.LittleEndian.Uint64(wantCV[lane*8:])
				g := binary.LittleEndian.Uint64(gotCV[lane*8:])
				if w != g {
					t.Errorf("instance %d, lane %d: got %016x, want %016x", inst, lane, g, w)
				}
			}
		}
	}
}

func BenchmarkProcessLeaves(b *testing.B) {
	const blockSize = 8192
	input := make([]byte, 8*blockSize)
	for i := range input {
		input[i] = byte(i)
	}
	var cvs [256]byte
	b.SetBytes(8 * blockSize)
	for b.Loop() {
		processLeaves(input, &cvs)
	}
}
