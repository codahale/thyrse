//go:build amd64 && !purego

#include "textflag.h"

// func XORAndCopy(dst, a, b []byte)
//
// For each i: dst[i] = a[i] ^ b[i], b[i] = dst[i].
// Uses SSE2 to process 16 bytes at a time.
TEXT ·XORAndCopy(SB), NOSPLIT, $0-72
	MOVQ dst_base+0(FP), DI  // dst pointer
	MOVQ a_base+24(FP), SI   // a pointer
	MOVQ b_base+48(FP), DX   // b pointer
	MOVQ dst_len+8(FP), CX   // length

loop16:
	CMPQ CX, $16
	JLT  tail
	MOVOU (SI), X0      // X0 = a[i:i+16]
	MOVOU (DX), X1      // X1 = b[i:i+16]
	PXOR  X1, X0        // X0 = a ^ b
	MOVOU X0, (DI)      // store to dst
	MOVOU X0, (DX)      // store to b
	ADDQ  $16, SI
	ADDQ  $16, DI
	ADDQ  $16, DX
	SUBQ  $16, CX
	JMP   loop16

tail:
	TESTQ CX, CX
	JZ    done

tail1:
	MOVB (SI), AL    // load a byte
	MOVB (DX), BL    // load b byte
	XORB AL, BL      // result = a ^ b
	MOVB BL, (DI)    // store to dst
	MOVB BL, (DX)    // store to b
	INCQ SI
	INCQ DI
	INCQ DX
	DECQ CX
	JNZ  tail1

done:
	RET
