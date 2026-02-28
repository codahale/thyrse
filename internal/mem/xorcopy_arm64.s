//go:build arm64 && !purego

#include "textflag.h"

// func XORAndCopy(dst, a, b []byte)
//
// For each i: dst[i] = a[i] ^ b[i], b[i] = dst[i].
// Uses NEON to process 16 bytes at a time.
TEXT ·XORAndCopy(SB), NOSPLIT, $0-72
	MOVD dst_base+0(FP), R0  // dst pointer
	MOVD a_base+24(FP), R1   // a pointer
	MOVD b_base+48(FP), R2   // b pointer
	MOVD dst_len+8(FP), R3   // length

loop16:
	CMP  $16, R3
	BLT  tail
	VLD1 (R1), [V0.B16]            // V0 = a[i:i+16]
	VLD1 (R2), [V1.B16]            // V1 = b[i:i+16]
	VEOR V0.B16, V1.B16, V2.B16    // V2 = a ^ b
	VST1 [V2.B16], (R0)            // store to dst
	VST1 [V2.B16], (R2)            // store to b
	ADD  $16, R0
	ADD  $16, R1
	ADD  $16, R2
	SUB  $16, R3
	B    loop16

tail:
	CBZ R3, done

tail1:
	MOVBU (R1), R4     // load a byte
	MOVBU (R2), R5     // load b byte
	EOR   R4, R5, R6   // result = a ^ b
	MOVB  R6, (R0)     // store to dst
	MOVB  R6, (R2)     // store to b
	ADD   $1, R0
	ADD   $1, R1
	ADD   $1, R2
	SUB   $1, R3
	CBNZ  R3, tail1

done:
	RET
