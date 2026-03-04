package keccak

// AvailableLanes is the preferred lane width for this CPU.
// It is set by platform-specific init() functions.
var AvailableLanes = 1

func (s *State1) Permute12() {
	if permute12x1Arch(s) {
		return
	}
	permute12x1Generic(s)
}

func (s *State2) Permute12() {
	if permute12x2Arch(s) {
		return
	}
	permute12x2Generic(s)
}

func (s *State4) Permute12() {
	if permute12x4Arch(s) {
		return
	}
	permute12x4Generic(s)
}

func (s *State8) Permute12() {
	if permute12x8Arch(s) {
		return
	}
	permute12x8Generic(s)
}
