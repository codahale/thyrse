// The encryptBlockAsm routine below is copied verbatim from aes_amd64.s in the
// Go standard library's crypto/internal/fips140/aes package, which carries:
//
//	Copyright 2012 The Go Authors. All rights reserved.
//	Use of this source code is governed by a BSD-style license.
//
// It encrypts a single AES block (AES-NI), reading the same natural-byte-order
// key schedule the gcm assembly uses, so the tag mask E_K(J0) can be computed
// without a second key expansion.

//go:build !purego

#include "textflag.h"

// func encryptBlockAsm(nr int, xk *uint32, dst *byte, src *byte)
// Requires: AES, SSE, SSE2
TEXT ·encryptBlockAsm(SB), NOSPLIT, $0-32
	MOVQ   nr+0(FP), CX
	MOVQ   xk+8(FP), AX
	MOVQ   dst+16(FP), DX
	MOVQ   src+24(FP), BX
	MOVUPS (AX), X1
	MOVUPS (BX), X0
	ADDQ   $0x10, AX
	PXOR   X1, X0
	SUBQ   $0x0c, CX
	JE     Lenc192
	JB     Lenc128
	MOVUPS (AX), X1
	AESENC X1, X0
	MOVUPS 16(AX), X1
	AESENC X1, X0
	ADDQ   $0x20, AX

Lenc192:
	MOVUPS (AX), X1
	AESENC X1, X0
	MOVUPS 16(AX), X1
	AESENC X1, X0
	ADDQ   $0x20, AX

Lenc128:
	MOVUPS     (AX), X1
	AESENC     X1, X0
	MOVUPS     16(AX), X1
	AESENC     X1, X0
	MOVUPS     32(AX), X1
	AESENC     X1, X0
	MOVUPS     48(AX), X1
	AESENC     X1, X0
	MOVUPS     64(AX), X1
	AESENC     X1, X0
	MOVUPS     80(AX), X1
	AESENC     X1, X0
	MOVUPS     96(AX), X1
	AESENC     X1, X0
	MOVUPS     112(AX), X1
	AESENC     X1, X0
	MOVUPS     128(AX), X1
	AESENC     X1, X0
	MOVUPS     144(AX), X1
	AESENCLAST X1, X0
	MOVUPS     X0, (DX)
	RET
