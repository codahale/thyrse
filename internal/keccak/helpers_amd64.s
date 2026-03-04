// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "keccak_amd64_avx2.h"
#include "keccak_amd64_avx512.h"

// ABSORB_LANE_X8_GATHER gathers one uint64 from 8 instances at the given byte
// offset from BX (data base pointer) using Z28 as the index vector
// ({0, stride, 2*stride, ..., 7*stride}), and XORs the result into Zlane.
// K1 is reset to all-ones before each gather.
#define ABSORB_LANE_X8_GATHER(offset, Zlane) \
	KXNORB	K1, K1, K1; \
	VPGATHERQQ	offset(BX)(Z28*1), K1, Z25; \
	VPXORQ	Z25, Zlane, Zlane

// func fastLoopAbsorb168x8AVX512(s *State8, in *byte, stride, n int)
//
// Fused absorb-permute loop: keeps state in Z0-Z24 across stripes,
// eliminating 50 VMOVDQU64s (25 load + 25 store = 3200 bytes) per stripe.
// Uses VPGATHERQQ to gather uint64s from 8 instances with stride.
//
// Frame: 384 bytes local (320 theta D + 64 gather indices), 32 bytes args.
// Register allocation:
//   AX   = state base pointer
//   BX   = data base pointer (single pointer, advances by 168 per stripe)
//   R11  = round constants pointer
//   R12  = remaining byte count
//   Z0-Z24  = Keccak state (persistent)
//   Z25-Z31 = scratch (absorb + permutation)
//   Z28     = gather index vector (reloaded from SP+320 each iteration)
//   K1      = gather mask (reset to all-ones before each VPGATHERQQ)
//   SP+0..SP+319   = theta D spill (permutation)
//   SP+320..SP+383 = gather index vector (computed once at entry)
TEXT ·fastLoopAbsorb168x8AVX512(SB), $384-32
	// Load arguments.
	MOVQ	s+0(FP), AX
	MOVQ	in+8(FP), BX
	MOVQ	stride+16(FP), R13
	MOVQ	n+24(FP), R12

	// Build gather index vector {0, stride, 2*stride, ..., 7*stride} at SP+320.
	MOVQ	$0, 320(SP)
	MOVQ	R13, 328(SP)
	LEAQ	(R13)(R13*1), R14
	MOVQ	R14, 336(SP)
	ADDQ	R13, R14
	MOVQ	R14, 344(SP)
	ADDQ	R13, R14
	MOVQ	R14, 352(SP)
	ADDQ	R13, R14
	MOVQ	R14, 360(SP)
	ADDQ	R13, R14
	MOVQ	R14, 368(SP)
	ADDQ	R13, R14
	MOVQ	R14, 376(SP)

	// Load state from memory into Z0-Z24.
	VMOVDQU64	0*64(AX), Z0
	VMOVDQU64	1*64(AX), Z1
	VMOVDQU64	2*64(AX), Z2
	VMOVDQU64	3*64(AX), Z3
	VMOVDQU64	4*64(AX), Z4
	VMOVDQU64	5*64(AX), Z5
	VMOVDQU64	6*64(AX), Z6
	VMOVDQU64	7*64(AX), Z7
	VMOVDQU64	8*64(AX), Z8
	VMOVDQU64	9*64(AX), Z9
	VMOVDQU64	10*64(AX), Z10
	VMOVDQU64	11*64(AX), Z11
	VMOVDQU64	12*64(AX), Z12
	VMOVDQU64	13*64(AX), Z13
	VMOVDQU64	14*64(AX), Z14
	VMOVDQU64	15*64(AX), Z15
	VMOVDQU64	16*64(AX), Z16
	VMOVDQU64	17*64(AX), Z17
	VMOVDQU64	18*64(AX), Z18
	VMOVDQU64	19*64(AX), Z19
	VMOVDQU64	20*64(AX), Z20
	VMOVDQU64	21*64(AX), Z21
	VMOVDQU64	22*64(AX), Z22
	VMOVDQU64	23*64(AX), Z23
	VMOVDQU64	24*64(AX), Z24

loop:
	CMPQ	R12, $168
	JB	done

	// Reload gather index vector (Z28 is clobbered by X8_THETA_AVX512).
	VMOVDQU64	320(SP), Z28

	// Absorb: XOR 21 rate lanes (168 bytes / 8 = 21 uint64s) from 8 inputs via gather.
	ABSORB_LANE_X8_GATHER(0*8, Z0)
	ABSORB_LANE_X8_GATHER(1*8, Z1)
	ABSORB_LANE_X8_GATHER(2*8, Z2)
	ABSORB_LANE_X8_GATHER(3*8, Z3)
	ABSORB_LANE_X8_GATHER(4*8, Z4)
	ABSORB_LANE_X8_GATHER(5*8, Z5)
	ABSORB_LANE_X8_GATHER(6*8, Z6)
	ABSORB_LANE_X8_GATHER(7*8, Z7)
	ABSORB_LANE_X8_GATHER(8*8, Z8)
	ABSORB_LANE_X8_GATHER(9*8, Z9)
	ABSORB_LANE_X8_GATHER(10*8, Z10)
	ABSORB_LANE_X8_GATHER(11*8, Z11)
	ABSORB_LANE_X8_GATHER(12*8, Z12)
	ABSORB_LANE_X8_GATHER(13*8, Z13)
	ABSORB_LANE_X8_GATHER(14*8, Z14)
	ABSORB_LANE_X8_GATHER(15*8, Z15)
	ABSORB_LANE_X8_GATHER(16*8, Z16)
	ABSORB_LANE_X8_GATHER(17*8, Z17)
	ABSORB_LANE_X8_GATHER(18*8, Z18)
	ABSORB_LANE_X8_GATHER(19*8, Z19)
	ABSORB_LANE_X8_GATHER(20*8, Z20)

	// Permute: 12 rounds = 3 × 4 rounds, starting at round constant offset +192.
	LEAQ	round_consts_2x+192(SB), R11
	X8_4ROUNDS_AVX512(0, 16, 32, 48)
	X8_4ROUNDS_AVX512(64, 80, 96, 112)
	X8_4ROUNDS_AVX512(128, 144, 160, 176)

	// Advance data pointer by 168 bytes, decrement remaining.
	ADDQ	$168, BX
	SUBQ	$168, R12
	JMP	loop

done:
	// Store state back to memory.
	VMOVDQU64	Z0, 0*64(AX)
	VMOVDQU64	Z1, 1*64(AX)
	VMOVDQU64	Z2, 2*64(AX)
	VMOVDQU64	Z3, 3*64(AX)
	VMOVDQU64	Z4, 4*64(AX)
	VMOVDQU64	Z5, 5*64(AX)
	VMOVDQU64	Z6, 6*64(AX)
	VMOVDQU64	Z7, 7*64(AX)
	VMOVDQU64	Z8, 8*64(AX)
	VMOVDQU64	Z9, 9*64(AX)
	VMOVDQU64	Z10, 10*64(AX)
	VMOVDQU64	Z11, 11*64(AX)
	VMOVDQU64	Z12, 12*64(AX)
	VMOVDQU64	Z13, 13*64(AX)
	VMOVDQU64	Z14, 14*64(AX)
	VMOVDQU64	Z15, 15*64(AX)
	VMOVDQU64	Z16, 16*64(AX)
	VMOVDQU64	Z17, 17*64(AX)
	VMOVDQU64	Z18, 18*64(AX)
	VMOVDQU64	Z19, 19*64(AX)
	VMOVDQU64	Z20, 20*64(AX)
	VMOVDQU64	Z21, 21*64(AX)
	VMOVDQU64	Z22, 22*64(AX)
	VMOVDQU64	Z23, 23*64(AX)
	VMOVDQU64	Z24, 24*64(AX)
	VZEROUPPER
	RET

