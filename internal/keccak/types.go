package keccak

import "encoding/binary"

const (
	// StateBytes is the size of a Keccak-p[1600] state in bytes.
	StateBytes = 200
	// Lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	Lanes = StateBytes / 8
)

// State1 is a single lane-major Keccak-p[1600] state.
type State1 struct {
	a [Lanes]uint64
}

// LoadFromBytes loads a [200]byte state into lane-major form.
func (s *State1) LoadFromBytes(b *[StateBytes]byte) {
	for i := range Lanes {
		s.a[i] = binary.LittleEndian.Uint64(b[i*8 : i*8+8])
	}
}

// StoreToBytes stores lane-major state back to a [200]byte.
func (s *State1) StoreToBytes(b *[StateBytes]byte) {
	for i := range Lanes {
		binary.LittleEndian.PutUint64(b[i*8:i*8+8], s.a[i])
	}
}

// State2 is a pair of lane-major Keccak-p[1600] states.
type State2 struct {
	a [Lanes][2]uint64
}

// State4 is four lane-major Keccak-p[1600] states.
type State4 struct {
	a [Lanes][4]uint64
}

// State8 is eight lane-major Keccak-p[1600] states.
type State8 struct {
	a [Lanes][8]uint64
}
