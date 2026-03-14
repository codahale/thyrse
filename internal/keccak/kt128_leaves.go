package keccak

import "encoding/binary"

// ProcessLeavesKT128 computes 8 KT128 leaf chain values from 8 contiguous
// 8192-byte chunks in input, writing the 8×32-byte CVs to cvs.
// Input must be exactly 8×8192 = 65536 bytes.
func ProcessLeavesKT128(input []byte, cvs *[256]byte) {
	if processLeavesKT128Arch(input, cvs) {
		return
	}
	processLeavesKT128Generic(input, cvs)
}

// processLeavesKT128Generic computes 8 leaf CVs using 8 independent State1 instances.
func processLeavesKT128Generic(input []byte, cvs *[256]byte) {
	const (
		blockSize = 8192
		leafDS    = 0x0B
	)
	for inst := range 8 {
		var s State1
		off := inst * blockSize
		s.AbsorbAll(input[off:off+blockSize], leafDS)
		// Extract CV = first 4 lanes (32 bytes).
		binary.LittleEndian.PutUint64(cvs[inst*32:], s.a[0])
		binary.LittleEndian.PutUint64(cvs[inst*32+8:], s.a[1])
		binary.LittleEndian.PutUint64(cvs[inst*32+16:], s.a[2])
		binary.LittleEndian.PutUint64(cvs[inst*32+24:], s.a[3])
	}
}
