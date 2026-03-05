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

// LoadFromBytes interleaves two [200]byte states into lane-major form.
func (s *State2) LoadFromBytes(b0, b1 *[StateBytes]byte) {
	for i := range Lanes {
		s.a[i][0] = binary.LittleEndian.Uint64(b0[i*8 : i*8+8])
		s.a[i][1] = binary.LittleEndian.Uint64(b1[i*8 : i*8+8])
	}
}

// StoreToBytes deinterleaves lane-major state back to two [200]byte states.
func (s *State2) StoreToBytes(b0, b1 *[StateBytes]byte) {
	for i := range Lanes {
		binary.LittleEndian.PutUint64(b0[i*8:i*8+8], s.a[i][0])
		binary.LittleEndian.PutUint64(b1[i*8:i*8+8], s.a[i][1])
	}
}

// State4 is four lane-major Keccak-p[1600] states.
type State4 struct {
	a [Lanes][4]uint64
}

// LoadFromBytes interleaves four [200]byte states into lane-major form.
func (s *State4) LoadFromBytes(b0, b1, b2, b3 *[StateBytes]byte) {
	for i := range Lanes {
		s.a[i][0] = binary.LittleEndian.Uint64(b0[i*8 : i*8+8])
		s.a[i][1] = binary.LittleEndian.Uint64(b1[i*8 : i*8+8])
		s.a[i][2] = binary.LittleEndian.Uint64(b2[i*8 : i*8+8])
		s.a[i][3] = binary.LittleEndian.Uint64(b3[i*8 : i*8+8])
	}
}

// StoreToBytes deinterleaves lane-major state back to four [200]byte states.
func (s *State4) StoreToBytes(b0, b1, b2, b3 *[StateBytes]byte) {
	for i := range Lanes {
		binary.LittleEndian.PutUint64(b0[i*8:i*8+8], s.a[i][0])
		binary.LittleEndian.PutUint64(b1[i*8:i*8+8], s.a[i][1])
		binary.LittleEndian.PutUint64(b2[i*8:i*8+8], s.a[i][2])
		binary.LittleEndian.PutUint64(b3[i*8:i*8+8], s.a[i][3])
	}
}

// State8 is eight lane-major Keccak-p[1600] states.
type State8 struct {
	a [Lanes][8]uint64
}
