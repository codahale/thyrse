package keccak

const (
	// StateBytes is the size of a Keccak-p[1600] state in bytes.
	StateBytes = 200
	// Lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	Lanes = StateBytes / 8
)

// State1 is a single lane-major Keccak-p[1600] state.
type State1 struct {
	A [Lanes]uint64
}

// State8 is eight lane-major Keccak-p[1600] states.
type State8 struct {
	A [Lanes][8]uint64
}
