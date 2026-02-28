//go:build amd64 && !purego

#include "textflag.h"

// func XORAndReplace(dst, src, state []byte)
//
// For each i: dst[i] = src[i] ^ state[i], state[i] = src[i].
// Uses SSE2 to process 16 bytes at a time.
TEXT ·XORAndReplace(SB), NOSPLIT, $0-72
	MOVQ dst_base+0(FP), DI    // dst pointer
	MOVQ src_base+24(FP), SI   // src pointer
	MOVQ state_base+48(FP), DX // state pointer
	MOVQ dst_len+8(FP), CX     // length

loop16:
	CMPQ CX, $16
	JLT  tail
	MOVOU (SI), X0      // X0 = src[i:i+16]
	MOVOU (DX), X1      // X1 = state[i:i+16]
	MOVOU X0, X2        // X2 = copy of src
	PXOR  X1, X0        // X0 = src ^ state = plaintext
	MOVOU X0, (DI)      // store plaintext to dst
	MOVOU X2, (DX)      // store src into state
	ADDQ  $16, SI
	ADDQ  $16, DI
	ADDQ  $16, DX
	SUBQ  $16, CX
	JMP   loop16

tail:
	TESTQ CX, CX
	JZ    done

tail1:
	MOVB (SI), AL    // load src byte
	MOVB (DX), BL    // load state byte
	XORB AL, BL      // plaintext = src ^ state
	MOVB BL, (DI)    // store plaintext
	MOVB AL, (DX)    // store src into state
	INCQ SI
	INCQ DI
	INCQ DX
	DECQ CX
	JNZ  tail1

done:
	RET
