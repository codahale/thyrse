//go:build amd64 && !purego

#include "textflag.h"

// func XORInPlace(dst, src []byte)
//
// Sets dst[i] ^= src[i] for each i.
// Uses SSE2 to process 16 bytes at a time.
TEXT ·XORInPlace(SB), NOSPLIT, $0-48
	MOVQ dst_base+0(FP), DI  // dst pointer
	MOVQ src_base+24(FP), SI // src pointer
	MOVQ dst_len+8(FP), CX   // length

loop16:
	CMPQ CX, $16
	JLT  tail
	MOVOU (DI), X0      // X0 = dst[i:i+16]
	MOVOU (SI), X1      // X1 = src[i:i+16]
	PXOR  X1, X0        // X0 = dst ^ src
	MOVOU X0, (DI)      // store back to dst
	ADDQ  $16, SI
	ADDQ  $16, DI
	SUBQ  $16, CX
	JMP   loop16

tail:
	TESTQ CX, CX
	JZ    done

tail1:
	MOVB (DI), AL    // load dst byte
	MOVB (SI), BL    // load src byte
	XORB BL, AL      // dst ^= src
	MOVB AL, (DI)    // store back
	INCQ SI
	INCQ DI
	DECQ CX
	JNZ  tail1

done:
	RET
