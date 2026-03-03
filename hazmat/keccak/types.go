package keccak

const (
	// StateBytes is the size of a Keccak-p[1600] state in bytes.
	StateBytes = 200
	// Lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	Lanes = 25
)

// State1 is a single lane-major Keccak-p[1600] state.
type State1 struct {
	a [Lanes]uint64
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
