package kt128

// processLeaves computes 8 KT128 leaf chain values from 8 contiguous
// 8192-byte chunks in input, writing the 8×32-byte CVs to cvs.
// Input must be exactly 8×8192 = 65536 bytes.
func processLeaves(input []byte, cvs *[256]byte) {
	if processLeavesArch(input, cvs) {
		return
	}
	processLeavesGeneric(input, cvs)
}

// processLeavesGeneric computes 8 leaf CVs using 8 independent State1 instances.
func processLeavesGeneric(input []byte, cvs *[256]byte) {
	for inst := range 8 {
		var s sponge
		off := inst * BlockSize
		s.absorbAll(input[off:off+BlockSize], leafDS)
		// Extract CV = first 4 lanes (32 bytes).
		s.squeeze(cvs[inst*32 : inst*32+32])
	}
}
