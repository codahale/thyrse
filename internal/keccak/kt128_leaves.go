package keccak

// ProcessLeavesKT128 computes 8 KT128 leaf chain values from 8 contiguous
// 8192-byte chunks in input. After return, the post-permute state for each
// instance is stored in s (lanes 0-3 hold the CVs) for direct consumption
// via AbsorbCVx8. Input must be exactly 8×8192 = 65536 bytes.
func ProcessLeavesKT128(input []byte, s *State8) {
	if processLeavesKT128Arch(input, s) {
		return
	}
	processLeavesKT128Generic(input, s)
}

// processLeavesKT128Generic computes 8 leaf states using 8 independent State1
// instances and packs results into a State8.
func processLeavesKT128Generic(input []byte, s *State8) {
	const (
		blockSize = 8192
		leafDS    = 0x0B
	)
	for inst := range 8 {
		var s1 State1
		off := inst * blockSize
		s1.AbsorbAll(input[off:off+blockSize], leafDS)
		for lane := range lanes {
			s.a[lane][inst] = s1.a[lane]
		}
	}
	s.pos = 0
}
