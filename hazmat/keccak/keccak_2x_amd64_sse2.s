// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego && (sse2 || avx2) && !avx512

#include "textflag.h"

#define ROT64_SSE2(reg, amount) \
	MOVOU	reg, X13; \
	PSLLQ	$amount, reg; \
	PSRLQ	$(64-amount), X13; \
	POR	X13, reg

#define CHI_SSE2(base) \
	MOVOU	X0, X10; \
	MOVOU	X1, X11; \
	/* out[0] = bc0 ^ (~bc1 & bc2) */ \
	MOVOU	X1, X12; \
	PANDN	X2, X12; \
	PXOR	X0, X12; \
	MOVOU	X12, (base+0)*16(R9); \
	/* out[1] = bc1 ^ (~bc2 & bc3) */ \
	MOVOU	X2, X12; \
	PANDN	X3, X12; \
	PXOR	X1, X12; \
	MOVOU	X12, (base+1)*16(R9); \
	/* out[2] = bc2 ^ (~bc3 & bc4) */ \
	MOVOU	X3, X12; \
	PANDN	X4, X12; \
	PXOR	X2, X12; \
	MOVOU	X12, (base+2)*16(R9); \
	/* out[3] = bc3 ^ (~bc4 & bc0_saved) */ \
	MOVOU	X4, X12; \
	PANDN	X10, X12; \
	PXOR	X3, X12; \
	MOVOU	X12, (base+3)*16(R9); \
	/* out[4] = bc4 ^ (~bc0_saved & bc1_saved) */ \
	PANDN	X11, X10; \
	PXOR	X4, X10; \
	MOVOU	X10, (base+4)*16(R9)

#define CHI_IOTA_SSE2(base) \
	MOVOU	X0, X10; \
	MOVOU	X1, X11; \
	MOVOU	X1, X12; \
	PANDN	X2, X12; \
	PXOR	X0, X12; \
	PXOR	X15, X12; \
	MOVOU	X12, (base+0)*16(R9); \
	MOVOU	X2, X12; \
	PANDN	X3, X12; \
	PXOR	X1, X12; \
	MOVOU	X12, (base+1)*16(R9); \
	MOVOU	X3, X12; \
	PANDN	X4, X12; \
	PXOR	X2, X12; \
	MOVOU	X12, (base+2)*16(R9); \
	MOVOU	X4, X12; \
	PANDN	X10, X12; \
	PXOR	X3, X12; \
	MOVOU	X12, (base+3)*16(R9); \
	PANDN	X11, X10; \
	PXOR	X4, X10; \
	MOVOU	X10, (base+4)*16(R9)

TEXT ·p1600x2SSE2(SB), $800-16
	MOVQ	a+0(FP), DI
	MOVQ	b+8(FP), SI

	// Load 25 lane pairs from state1 (DI) and state2 (SI), combine into
	// [state1_lane | state2_lane] XMM format, and store to buffer A on stack.
	// Buffer A is at 0(SP), buffer B is at 400(SP).
	MOVQ	(DI), X0
	MOVQ	(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 0*16(SP)

	MOVQ	8(DI), X0
	MOVQ	8(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 1*16(SP)

	MOVQ	16(DI), X0
	MOVQ	16(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 2*16(SP)

	MOVQ	24(DI), X0
	MOVQ	24(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 3*16(SP)

	MOVQ	32(DI), X0
	MOVQ	32(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 4*16(SP)

	MOVQ	40(DI), X0
	MOVQ	40(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 5*16(SP)

	MOVQ	48(DI), X0
	MOVQ	48(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 6*16(SP)

	MOVQ	56(DI), X0
	MOVQ	56(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 7*16(SP)

	MOVQ	64(DI), X0
	MOVQ	64(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 8*16(SP)

	MOVQ	72(DI), X0
	MOVQ	72(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 9*16(SP)

	MOVQ	80(DI), X0
	MOVQ	80(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 10*16(SP)

	MOVQ	88(DI), X0
	MOVQ	88(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 11*16(SP)

	MOVQ	96(DI), X0
	MOVQ	96(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 12*16(SP)

	MOVQ	104(DI), X0
	MOVQ	104(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 13*16(SP)

	MOVQ	112(DI), X0
	MOVQ	112(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 14*16(SP)

	MOVQ	120(DI), X0
	MOVQ	120(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 15*16(SP)

	MOVQ	128(DI), X0
	MOVQ	128(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 16*16(SP)

	MOVQ	136(DI), X0
	MOVQ	136(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 17*16(SP)

	MOVQ	144(DI), X0
	MOVQ	144(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 18*16(SP)

	MOVQ	152(DI), X0
	MOVQ	152(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 19*16(SP)

	MOVQ	160(DI), X0
	MOVQ	160(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 20*16(SP)

	MOVQ	168(DI), X0
	MOVQ	168(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 21*16(SP)

	MOVQ	176(DI), X0
	MOVQ	176(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 22*16(SP)

	MOVQ	184(DI), X0
	MOVQ	184(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 23*16(SP)

	MOVQ	192(DI), X0
	MOVQ	192(SI), X1
	PUNPCKLQDQ	X1, X0
	MOVOU	X0, 24*16(SP)

	// Set up loop
	LEAQ	0(SP), R8                          // source = buf A
	LEAQ	400(SP), R9                        // dest = buf B
	LEAQ	round_consts_2x<>+192(SB), R11     // RC start (round 12)
	MOVQ	$12, R10

	PCALIGN	$16
round_loop:
	// === THETA ===
	// Column parities: C[x] = lane[x] ^ lane[x+5] ^ lane[x+10] ^ lane[x+15] ^ lane[x+20]
	// Note: all memory loads use MOVOU (unaligned) because the stack
	// buffer may not be 16-byte aligned. PXOR with a memory operand
	// requires 16-byte alignment and would fault on real AMD64 hardware.
	MOVOU	0*16(R8), X0
	MOVOU	5*16(R8), X14
	PXOR	X14, X0
	MOVOU	10*16(R8), X14
	PXOR	X14, X0
	MOVOU	15*16(R8), X14
	PXOR	X14, X0
	MOVOU	20*16(R8), X14
	PXOR	X14, X0             // X0 = C[0]

	MOVOU	1*16(R8), X1
	MOVOU	6*16(R8), X14
	PXOR	X14, X1
	MOVOU	11*16(R8), X14
	PXOR	X14, X1
	MOVOU	16*16(R8), X14
	PXOR	X14, X1
	MOVOU	21*16(R8), X14
	PXOR	X14, X1             // X1 = C[1]

	MOVOU	2*16(R8), X2
	MOVOU	7*16(R8), X14
	PXOR	X14, X2
	MOVOU	12*16(R8), X14
	PXOR	X14, X2
	MOVOU	17*16(R8), X14
	PXOR	X14, X2
	MOVOU	22*16(R8), X14
	PXOR	X14, X2             // X2 = C[2]

	MOVOU	3*16(R8), X3
	MOVOU	8*16(R8), X14
	PXOR	X14, X3
	MOVOU	13*16(R8), X14
	PXOR	X14, X3
	MOVOU	18*16(R8), X14
	PXOR	X14, X3
	MOVOU	23*16(R8), X14
	PXOR	X14, X3             // X3 = C[3]

	MOVOU	4*16(R8), X4
	MOVOU	9*16(R8), X14
	PXOR	X14, X4
	MOVOU	14*16(R8), X14
	PXOR	X14, X4
	MOVOU	19*16(R8), X14
	PXOR	X14, X4
	MOVOU	24*16(R8), X14
	PXOR	X14, X4             // X4 = C[4]

	// Diffusion: D[x] = C[(x-1)%5] ^ ROL64(C[(x+1)%5], 1)
	// D[0] = C[4] ^ ROL64(C[1], 1)
	MOVOU	X1, X5
	ROT64_SSE2(X5, 1)
	PXOR	X4, X5              // X5 = D[0]

	// D[1] = C[0] ^ ROL64(C[2], 1)
	MOVOU	X2, X6
	ROT64_SSE2(X6, 1)
	PXOR	X0, X6              // X6 = D[1]

	// D[2] = C[1] ^ ROL64(C[3], 1)
	MOVOU	X3, X7
	ROT64_SSE2(X7, 1)
	PXOR	X1, X7              // X7 = D[2]

	// D[3] = C[2] ^ ROL64(C[4], 1)
	MOVOU	X4, X8
	ROT64_SSE2(X8, 1)
	PXOR	X2, X8              // X8 = D[3]

	// D[4] = C[3] ^ ROL64(C[0], 1)
	MOVOU	X0, X9
	ROT64_SSE2(X9, 1)
	PXOR	X3, X9              // X9 = D[4]

	// === RHO + PI + CHI + IOTA ===
	// Combined step: for each output row, load source lanes (at pi-inverse
	// positions), XOR with theta D values, rotate by rho amounts, then
	// apply chi (and iota for row 0).
	//
	// Output row 0 (lanes 0-4):
	//   bc0: src[0]  ^ d0, rot 0
	//   bc1: src[6]  ^ d1, rot 44
	//   bc2: src[12] ^ d2, rot 43
	//   bc3: src[18] ^ d3, rot 21
	//   bc4: src[24] ^ d4, rot 14

	MOVOU	0*16(R8), X0
	PXOR	X5, X0
	// rot 0: no rotation

	MOVOU	6*16(R8), X1
	PXOR	X6, X1
	ROT64_SSE2(X1, 44)

	MOVOU	12*16(R8), X2
	PXOR	X7, X2
	ROT64_SSE2(X2, 43)

	MOVOU	18*16(R8), X3
	PXOR	X8, X3
	ROT64_SSE2(X3, 21)

	MOVOU	24*16(R8), X4
	PXOR	X9, X4
	ROT64_SSE2(X4, 14)

	MOVOU	(R11), X15          // load round constant
	CHI_IOTA_SSE2(0)

	// Output row 1 (lanes 5-9):
	//   bc0: src[3]  ^ d3, rot 28
	//   bc1: src[9]  ^ d4, rot 20
	//   bc2: src[10] ^ d0, rot 3
	//   bc3: src[16] ^ d1, rot 45
	//   bc4: src[22] ^ d2, rot 61

	MOVOU	3*16(R8), X0
	PXOR	X8, X0
	ROT64_SSE2(X0, 28)

	MOVOU	9*16(R8), X1
	PXOR	X9, X1
	ROT64_SSE2(X1, 20)

	MOVOU	10*16(R8), X2
	PXOR	X5, X2
	ROT64_SSE2(X2, 3)

	MOVOU	16*16(R8), X3
	PXOR	X6, X3
	ROT64_SSE2(X3, 45)

	MOVOU	22*16(R8), X4
	PXOR	X7, X4
	ROT64_SSE2(X4, 61)

	CHI_SSE2(5)

	// Output row 2 (lanes 10-14):
	//   bc0: src[1]  ^ d1, rot 1
	//   bc1: src[7]  ^ d2, rot 6
	//   bc2: src[13] ^ d3, rot 25
	//   bc3: src[19] ^ d4, rot 8
	//   bc4: src[20] ^ d0, rot 18

	MOVOU	1*16(R8), X0
	PXOR	X6, X0
	ROT64_SSE2(X0, 1)

	MOVOU	7*16(R8), X1
	PXOR	X7, X1
	ROT64_SSE2(X1, 6)

	MOVOU	13*16(R8), X2
	PXOR	X8, X2
	ROT64_SSE2(X2, 25)

	MOVOU	19*16(R8), X3
	PXOR	X9, X3
	ROT64_SSE2(X3, 8)

	MOVOU	20*16(R8), X4
	PXOR	X5, X4
	ROT64_SSE2(X4, 18)

	CHI_SSE2(10)

	// Output row 3 (lanes 15-19):
	//   bc0: src[4]  ^ d4, rot 27
	//   bc1: src[5]  ^ d0, rot 36
	//   bc2: src[11] ^ d1, rot 10
	//   bc3: src[17] ^ d2, rot 15
	//   bc4: src[23] ^ d3, rot 56

	MOVOU	4*16(R8), X0
	PXOR	X9, X0
	ROT64_SSE2(X0, 27)

	MOVOU	5*16(R8), X1
	PXOR	X5, X1
	ROT64_SSE2(X1, 36)

	MOVOU	11*16(R8), X2
	PXOR	X6, X2
	ROT64_SSE2(X2, 10)

	MOVOU	17*16(R8), X3
	PXOR	X7, X3
	ROT64_SSE2(X3, 15)

	MOVOU	23*16(R8), X4
	PXOR	X8, X4
	ROT64_SSE2(X4, 56)

	CHI_SSE2(15)

	// Output row 4 (lanes 20-24):
	//   bc0: src[2]  ^ d2, rot 62
	//   bc1: src[8]  ^ d3, rot 55
	//   bc2: src[14] ^ d4, rot 39
	//   bc3: src[15] ^ d0, rot 41
	//   bc4: src[21] ^ d1, rot 2

	MOVOU	2*16(R8), X0
	PXOR	X7, X0
	ROT64_SSE2(X0, 62)

	MOVOU	8*16(R8), X1
	PXOR	X8, X1
	ROT64_SSE2(X1, 55)

	MOVOU	14*16(R8), X2
	PXOR	X9, X2
	ROT64_SSE2(X2, 39)

	MOVOU	15*16(R8), X3
	PXOR	X5, X3
	ROT64_SSE2(X3, 41)

	MOVOU	21*16(R8), X4
	PXOR	X6, X4
	ROT64_SSE2(X4, 2)

	CHI_SSE2(20)

	// Swap source/dest and advance round constant
	XCHGQ	R8, R9
	ADDQ	$16, R11
	SUBQ	$1, R10
	JNZ	round_loop

	// === STORE RESULTS ===
	// R8 now points to the final output buffer. Extract lane pairs
	// back into state1 (DI) and state2 (SI).
	MOVOU	0*16(R8), X0
	MOVQ	X0, (DI)
	PSRLDQ	$8, X0
	MOVQ	X0, (SI)

	MOVOU	1*16(R8), X0
	MOVQ	X0, 8(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 8(SI)

	MOVOU	2*16(R8), X0
	MOVQ	X0, 16(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 16(SI)

	MOVOU	3*16(R8), X0
	MOVQ	X0, 24(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 24(SI)

	MOVOU	4*16(R8), X0
	MOVQ	X0, 32(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 32(SI)

	MOVOU	5*16(R8), X0
	MOVQ	X0, 40(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 40(SI)

	MOVOU	6*16(R8), X0
	MOVQ	X0, 48(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 48(SI)

	MOVOU	7*16(R8), X0
	MOVQ	X0, 56(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 56(SI)

	MOVOU	8*16(R8), X0
	MOVQ	X0, 64(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 64(SI)

	MOVOU	9*16(R8), X0
	MOVQ	X0, 72(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 72(SI)

	MOVOU	10*16(R8), X0
	MOVQ	X0, 80(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 80(SI)

	MOVOU	11*16(R8), X0
	MOVQ	X0, 88(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 88(SI)

	MOVOU	12*16(R8), X0
	MOVQ	X0, 96(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 96(SI)

	MOVOU	13*16(R8), X0
	MOVQ	X0, 104(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 104(SI)

	MOVOU	14*16(R8), X0
	MOVQ	X0, 112(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 112(SI)

	MOVOU	15*16(R8), X0
	MOVQ	X0, 120(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 120(SI)

	MOVOU	16*16(R8), X0
	MOVQ	X0, 128(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 128(SI)

	MOVOU	17*16(R8), X0
	MOVQ	X0, 136(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 136(SI)

	MOVOU	18*16(R8), X0
	MOVQ	X0, 144(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 144(SI)

	MOVOU	19*16(R8), X0
	MOVQ	X0, 152(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 152(SI)

	MOVOU	20*16(R8), X0
	MOVQ	X0, 160(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 160(SI)

	MOVOU	21*16(R8), X0
	MOVQ	X0, 168(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 168(SI)

	MOVOU	22*16(R8), X0
	MOVQ	X0, 176(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 176(SI)

	MOVOU	23*16(R8), X0
	MOVQ	X0, 184(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 184(SI)

	MOVOU	24*16(R8), X0
	MOVQ	X0, 192(DI)
	PSRLDQ	$8, X0
	MOVQ	X0, 192(SI)

	RET

DATA	round_consts_2x<>+0x000(SB)/8, $0x0000000000000001
DATA	round_consts_2x<>+0x008(SB)/8, $0x0000000000000001
DATA	round_consts_2x<>+0x010(SB)/8, $0x0000000000008082
DATA	round_consts_2x<>+0x018(SB)/8, $0x0000000000008082
DATA	round_consts_2x<>+0x020(SB)/8, $0x800000000000808a
DATA	round_consts_2x<>+0x028(SB)/8, $0x800000000000808a
DATA	round_consts_2x<>+0x030(SB)/8, $0x8000000080008000
DATA	round_consts_2x<>+0x038(SB)/8, $0x8000000080008000
DATA	round_consts_2x<>+0x040(SB)/8, $0x000000000000808b
DATA	round_consts_2x<>+0x048(SB)/8, $0x000000000000808b
DATA	round_consts_2x<>+0x050(SB)/8, $0x0000000080000001
DATA	round_consts_2x<>+0x058(SB)/8, $0x0000000080000001
DATA	round_consts_2x<>+0x060(SB)/8, $0x8000000080008081
DATA	round_consts_2x<>+0x068(SB)/8, $0x8000000080008081
DATA	round_consts_2x<>+0x070(SB)/8, $0x8000000000008009
DATA	round_consts_2x<>+0x078(SB)/8, $0x8000000000008009
DATA	round_consts_2x<>+0x080(SB)/8, $0x000000000000008a
DATA	round_consts_2x<>+0x088(SB)/8, $0x000000000000008a
DATA	round_consts_2x<>+0x090(SB)/8, $0x0000000000000088
DATA	round_consts_2x<>+0x098(SB)/8, $0x0000000000000088
DATA	round_consts_2x<>+0x0A0(SB)/8, $0x0000000080008009
DATA	round_consts_2x<>+0x0A8(SB)/8, $0x0000000080008009
DATA	round_consts_2x<>+0x0B0(SB)/8, $0x000000008000000a
DATA	round_consts_2x<>+0x0B8(SB)/8, $0x000000008000000a
DATA	round_consts_2x<>+0x0C0(SB)/8, $0x000000008000808b
DATA	round_consts_2x<>+0x0C8(SB)/8, $0x000000008000808b
DATA	round_consts_2x<>+0x0D0(SB)/8, $0x800000000000008b
DATA	round_consts_2x<>+0x0D8(SB)/8, $0x800000000000008b
DATA	round_consts_2x<>+0x0E0(SB)/8, $0x8000000000008089
DATA	round_consts_2x<>+0x0E8(SB)/8, $0x8000000000008089
DATA	round_consts_2x<>+0x0F0(SB)/8, $0x8000000000008003
DATA	round_consts_2x<>+0x0F8(SB)/8, $0x8000000000008003
DATA	round_consts_2x<>+0x100(SB)/8, $0x8000000000008002
DATA	round_consts_2x<>+0x108(SB)/8, $0x8000000000008002
DATA	round_consts_2x<>+0x110(SB)/8, $0x8000000000000080
DATA	round_consts_2x<>+0x118(SB)/8, $0x8000000000000080
DATA	round_consts_2x<>+0x120(SB)/8, $0x000000000000800a
DATA	round_consts_2x<>+0x128(SB)/8, $0x000000000000800a
DATA	round_consts_2x<>+0x130(SB)/8, $0x800000008000000a
DATA	round_consts_2x<>+0x138(SB)/8, $0x800000008000000a
DATA	round_consts_2x<>+0x140(SB)/8, $0x8000000080008081
DATA	round_consts_2x<>+0x148(SB)/8, $0x8000000080008081
DATA	round_consts_2x<>+0x150(SB)/8, $0x8000000000008080
DATA	round_consts_2x<>+0x158(SB)/8, $0x8000000000008080
DATA	round_consts_2x<>+0x160(SB)/8, $0x0000000080000001
DATA	round_consts_2x<>+0x168(SB)/8, $0x0000000080000001
DATA	round_consts_2x<>+0x170(SB)/8, $0x8000000080008008
DATA	round_consts_2x<>+0x178(SB)/8, $0x8000000080008008
GLOBL	round_consts_2x<>(SB), NOPTR|RODATA, $384
