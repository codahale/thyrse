// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "../keccak/permute_amd64_gp.h"
#include "../keccak/permute_amd64_avx2.h"
#include "../keccak/permute_amd64_avx512.h"

// func fastLoopAbsorb168x1(s *State1, in *byte, n int)
//
// Fused absorb-permute loop for scalar Keccak.
// Keeps state in DI between iterations.
//
// Frame: 216 bytes local (0-199 permutation scratch, 200 saved in ptr, 208 count), 24 bytes args.
// Register allocation matches p1600: DI = state, SP = scratch.
TEXT ·fastLoopAbsorb168x1(SB), $216-24
	MOVQ	s+0(FP), DI
	MOVQ	in+8(FP), AX
	MOVQ	n+16(FP), CX
	MOVQ	AX, 200(SP)
	MOVQ	CX, 208(SP)

	// Convert to internal representation (complement 6 lanes).
	NOTQ	8(DI)
	NOTQ	16(DI)
	NOTQ	64(DI)
	NOTQ	96(DI)
	NOTQ	136(DI)
	NOTQ	160(DI)

loop_x1:
	CMPQ	208(SP), $168
	JB	done_x1

	// Absorb: XOR 21 lanes from input into state.
	MOVQ	200(SP), AX
	MOVQ	0*8(AX), R10;  XORQ	R10, 0*8(DI)
	MOVQ	1*8(AX), R10;  XORQ	R10, 1*8(DI)
	MOVQ	2*8(AX), R10;  XORQ	R10, 2*8(DI)
	MOVQ	3*8(AX), R10;  XORQ	R10, 3*8(DI)
	MOVQ	4*8(AX), R10;  XORQ	R10, 4*8(DI)
	MOVQ	5*8(AX), R10;  XORQ	R10, 5*8(DI)
	MOVQ	6*8(AX), R10;  XORQ	R10, 6*8(DI)
	MOVQ	7*8(AX), R10;  XORQ	R10, 7*8(DI)
	MOVQ	8*8(AX), R10;  XORQ	R10, 8*8(DI)
	MOVQ	9*8(AX), R10;  XORQ	R10, 9*8(DI)
	MOVQ	10*8(AX), R10; XORQ	R10, 10*8(DI)
	MOVQ	11*8(AX), R10; XORQ	R10, 11*8(DI)
	MOVQ	12*8(AX), R10; XORQ	R10, 12*8(DI)
	MOVQ	13*8(AX), R10; XORQ	R10, 13*8(DI)
	MOVQ	14*8(AX), R10; XORQ	R10, 14*8(DI)
	MOVQ	15*8(AX), R10; XORQ	R10, 15*8(DI)
	MOVQ	16*8(AX), R10; XORQ	R10, 16*8(DI)
	MOVQ	17*8(AX), R10; XORQ	R10, 17*8(DI)
	MOVQ	18*8(AX), R10; XORQ	R10, 18*8(DI)
	MOVQ	19*8(AX), R10; XORQ	R10, 19*8(DI)
	MOVQ	20*8(AX), R10; XORQ	R10, 20*8(DI)
	ADDQ	$168, AX
	MOVQ	AX, 200(SP)
	SUBQ	$168, 208(SP)

	// Permute: compute column parities, then 12 unrolled rounds.
	MOVQ	(DI), SI
	MOVQ	8(DI), BP
	MOVQ	32(DI), R15
	XORQ	40(DI), SI
	XORQ	48(DI), BP
	XORQ	72(DI), R15
	XORQ	80(DI), SI
	XORQ	88(DI), BP
	XORQ	112(DI), R15
	XORQ	120(DI), SI
	XORQ	128(DI), BP
	XORQ	152(DI), R15
	XORQ	160(DI), SI
	XORQ	168(DI), BP
	MOVQ	176(DI), DX
	MOVQ	184(DI), R8
	XORQ	192(DI), R15

	KECCAK_ROUND(DI, SP, $0x000000008000808b)
	KECCAK_ROUND(SP, DI, $0x800000000000008b)
	KECCAK_ROUND(DI, SP, $0x8000000000008089)
	KECCAK_ROUND(SP, DI, $0x8000000000008003)
	KECCAK_ROUND(DI, SP, $0x8000000000008002)
	KECCAK_ROUND(SP, DI, $0x8000000000000080)
	KECCAK_ROUND(DI, SP, $0x000000000000800a)
	KECCAK_ROUND(SP, DI, $0x800000008000000a)
	KECCAK_ROUND(DI, SP, $0x8000000080008081)
	KECCAK_ROUND(SP, DI, $0x8000000000008080)
	KECCAK_ROUND(DI, SP, $0x0000000080000001)
	KECCAK_ROUND(SP, DI, $0x8000000080008008)

	JMP	loop_x1

done_x1:
	// Revert internal state.
	NOTQ	8(DI)
	NOTQ	16(DI)
	NOTQ	64(DI)
	NOTQ	96(DI)
	NOTQ	136(DI)
	NOTQ	160(DI)
	RET

// ============================================================================
// Rate-168 fused encrypt/decrypt + permute loops
// ============================================================================

// ENCRYPT_LANE_X1 encrypts one full lane (8 bytes) at offset i for x1.
// For non-complemented lanes. AX=src, BX=dst, DI=state. Clobbers R10.
#define ENCRYPT_LANE_X1(i) \
	MOVQ	i*8(AX), R10; \
	XORQ	R10, i*8(DI); \
	MOVQ	i*8(DI), R10; \
	MOVQ	R10, i*8(BX)

// fastLoopAbsorb168x1AVX512 absorbs full 168-byte blocks into State1 using
// AVX-512. State is kept in ZMM registers across absorb+permute iterations.
//
// func fastLoopAbsorb168x1AVX512(s *State1, in *byte, n int)
TEXT ·fastLoopAbsorb168x1AVX512(SB), NOSPLIT, $0-24
	MOVQ	s+0(FP), DI
	MOVQ	in+8(FP), SI
	MOVQ	n+16(FP), CX

	X1_SETUP_MASKS
	LEAQ	kt128_avx512_x1_consts(SB), R8
	X1_LOAD_CONSTS
	X1_LOAD_STATE

absorb_loop_x1_avx512:
	CMPQ	CX, $168
	JB	done_x1_avx512

	X1_ABSORB_168

	LEAQ	kt128_avx512_x1_iotas+96(SB), R10
	MOVL	$6, AX

round_loop_x1_avx512:
	X1_EVEN_ROUND
	X1_ODD_ROUND
	DECL	AX
	JNZ	round_loop_x1_avx512

	JMP	absorb_loop_x1_avx512

done_x1_avx512:
	X1_STORE_STATE
	VZEROUPPER
	RET
