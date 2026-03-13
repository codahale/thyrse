package keccak

import "math/bits"

const (
	// stateBytes is the size of a Keccak-p[1600] state in bytes.
	stateBytes = 200
	// lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	lanes = stateBytes / 8

	Rate = 168
)

func loadPartialLE(in []byte) uint64 {
	var v uint64
	for i := range in {
		v |= uint64(in[i]) << (8 * i)
	}
	return v
}

func storePartialLE(out []byte, v uint64) {
	for i := range out {
		out[i] = byte(v >> (8 * i))
	}
}

func xorByteInWord(w *uint64, pos int, b byte) {
	shift := uint((pos & 7) << 3)
	*w ^= uint64(b) << shift
}

var roundConstants = [24]uint64{ //nolint:gochecknoglobals
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008,
}

var rho = [24]uint{ //nolint:gochecknoglobals
	1, 3, 6, 10, 15, 21,
	28, 36, 45, 55, 2, 14,
	27, 41, 56, 8, 25, 43,
	62, 18, 39, 61, 20, 44,
}

var pi = [24]int{ //nolint:gochecknoglobals
	10, 7, 11, 17, 18, 3,
	5, 16, 8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22, 9, 6, 1,
}

func keccakP1600x12(a *[lanes]uint64) {
	var c [5]uint64
	for round := 12; round < 24; round++ {
		for i := range 5 {
			c[i] = a[i] ^ a[i+5] ^ a[i+10] ^ a[i+15] ^ a[i+20]
		}

		for i := range 5 {
			t := c[(i+4)%5] ^ bits.RotateLeft64(c[(i+1)%5], 1)
			for j := 0; j < lanes; j += 5 {
				a[j+i] ^= t
			}
		}

		t := a[1]
		for i := range 24 {
			j := pi[i]
			c0 := a[j]
			a[j] = bits.RotateLeft64(t, int(rho[i]))
			t = c0
		}

		for j := 0; j < lanes; j += 5 {
			for i := range 5 {
				c[i] = a[j+i]
			}
			for i := range 5 {
				a[j+i] = c[i] ^ (^c[(i+1)%5] & c[(i+2)%5])
			}
		}

		a[0] ^= roundConstants[round]
	}
}
