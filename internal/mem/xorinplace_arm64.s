//go:build arm64 && !purego

#include "textflag.h"

// func XORInPlace(dst, src []byte)
//
// Sets dst[i] ^= src[i] for each i.
// Uses NEON to process 16 bytes at a time.
TEXT ·XORInPlace(SB), NOSPLIT, $0-48
	MOVD dst_base+0(FP), R0  // dst pointer
	MOVD src_base+24(FP), R1 // src pointer
	MOVD dst_len+8(FP), R3   // length

loop16:
	CMP  $16, R3
	BLT  tail
	VLD1 (R0), [V0.B16]            // V0 = dst[i:i+16]
	VLD1 (R1), [V1.B16]            // V1 = src[i:i+16]
	VEOR V0.B16, V1.B16, V0.B16    // V0 = dst ^ src
	VST1 [V0.B16], (R0)            // store back to dst
	ADD  $16, R0
	ADD  $16, R1
	SUB  $16, R3
	B    loop16

tail:
	CBZ R3, done

tail1:
	MOVBU (R0), R4     // load dst byte
	MOVBU (R1), R5     // load src byte
	EOR   R4, R5, R4   // dst ^= src
	MOVB  R4, (R0)     // store back
	ADD   $1, R0
	ADD   $1, R1
	SUB   $1, R3
	CBNZ  R3, tail1

done:
	RET
