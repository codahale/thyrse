//go:build arm64 && !purego

#include "textflag.h"

// func XORAndReplace(dst, src, state []byte)
//
// For each i: dst[i] = src[i] ^ state[i], state[i] = src[i].
// Uses NEON to process 16 bytes at a time.
TEXT ·XORAndReplace(SB), NOSPLIT, $0-72
	MOVD dst_base+0(FP), R0    // dst pointer
	MOVD src_base+24(FP), R1   // src pointer
	MOVD state_base+48(FP), R2 // state pointer
	MOVD dst_len+8(FP), R3     // length

loop16:
	CMP  $16, R3
	BLT  tail
	VLD1 (R1), [V0.B16]            // V0 = src[i:i+16]
	VLD1 (R2), [V1.B16]            // V1 = state[i:i+16]
	VEOR V0.B16, V1.B16, V2.B16    // V2 = src ^ state = plaintext
	VST1 [V2.B16], (R0)            // store plaintext to dst
	VST1 [V0.B16], (R2)            // store src into state
	ADD  $16, R0
	ADD  $16, R1
	ADD  $16, R2
	SUB  $16, R3
	B    loop16

tail:
	CBZ R3, done

tail1:
	MOVBU (R1), R4     // load src byte
	MOVBU (R2), R5     // load state byte
	EOR   R4, R5, R6   // plaintext = src ^ state
	MOVB  R6, (R0)     // store plaintext
	MOVB  R4, (R2)     // store src into state
	ADD   $1, R0
	ADD   $1, R1
	ADD   $1, R2
	SUB   $1, R3
	CBNZ  R3, tail1

done:
	RET
