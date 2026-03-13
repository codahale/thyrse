package keccak

const (
	// StateBytes is the size of a Keccak-p[1600] state in bytes.
	StateBytes = 200
	// Lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	Lanes = StateBytes / 8
)

// State1 is a single lane-major Keccak-p[1600] state with duplex position tracking.
type State1 struct {
	a   [Lanes]uint64
	pos int
}

// State8 is eight lane-major Keccak-p[1600] states with shared duplex position tracking.
type State8 struct {
	a   [Lanes][8]uint64
	pos int
}
