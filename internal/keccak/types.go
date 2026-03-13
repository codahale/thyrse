package keccak

const (
	// stateBytes is the size of a Keccak-p[1600] state in bytes.
	stateBytes = 200
	// lanes is the number of 64-bit lanes in a Keccak-p[1600] state.
	lanes = stateBytes / 8
)

// State1 is a single lane-major Keccak-p[1600] state with duplex position tracking.
type State1 struct {
	a   [lanes]uint64
	pos int
}

// State8 is eight lane-major Keccak-p[1600] states with shared duplex position tracking.
type State8 struct {
	a   [lanes][8]uint64
	pos int
}
