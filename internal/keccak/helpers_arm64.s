// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "keccak_arm64.h"

// ABSORB_STRIPE_X2 XORs one 168-byte stripe from two input pointers (IN0, IN1)
// into state registers V0-V20 (21 rate lanes). Uses V25-V26 as temps.
// Each lane is {in0_val, in1_val} packed into a 128-bit vector.
#define ABSORB_STRIPE_X2(IN0, IN1) \
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V0.B16, V0.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V1.B16, V1.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V2.B16, V2.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V3.B16, V3.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V4.B16, V4.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V5.B16, V5.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V6.B16, V6.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V7.B16, V7.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V8.B16, V8.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V9.B16, V9.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V10.B16, V10.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V11.B16, V11.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V12.B16, V12.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V13.B16, V13.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V14.B16, V14.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V15.B16, V15.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V16.B16, V16.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V17.B16, V17.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V18.B16, V18.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V19.B16, V19.B16; \
	\
	VLD1	(IN0), [V25.D1]; ADD $8, IN0; \
	VLD1	(IN1), [V26.D1]; ADD $8, IN1; \
	VZIP1	V26.D2, V25.D2, V25.D2; \
	VEOR	V25.B16, V20.B16, V20.B16

// ABSORB_STRIPE_X1 XORs one 168-byte stripe from a single input pointer (IN)
// into state registers V0-V20 (21 rate lanes, .D1 only). Uses V25 as temp.
#define ABSORB_STRIPE_X1(IN) \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V0.B8, V0.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V1.B8, V1.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V2.B8, V2.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V3.B8, V3.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V4.B8, V4.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V5.B8, V5.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V6.B8, V6.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V7.B8, V7.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V8.B8, V8.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V9.B8, V9.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V10.B8, V10.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V11.B8, V11.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V12.B8, V12.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V13.B8, V13.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V14.B8, V14.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V15.B8, V15.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V16.B8, V16.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V17.B8, V17.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V18.B8, V18.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V19.B8, V19.B8; \
	VLD1	(IN), [V25.D1]; ADD $8, IN; VEOR V25.B8, V20.B8, V20.B8

// func fastLoopAbsorb168x2(s *State2, in *byte, stride, n int)
TEXT ·fastLoopAbsorb168x2(SB), NOSPLIT, $0-32
	MOVD	s+0(FP), R0
	MOVD	in+8(FP), R2
	MOVD	stride+16(FP), R5
	MOVD	n+24(FP), R4
	ADD	R2, R5, R3   // R3 = in + stride

	// Load lane-major state (25 lanes × 16 bytes = 400 bytes).
	VLD1.P	32(R0), [V0.D2, V1.D2]
	VLD1.P	32(R0), [V2.D2, V3.D2]
	VLD1.P	32(R0), [V4.D2, V5.D2]
	VLD1.P	32(R0), [V6.D2, V7.D2]
	VLD1.P	32(R0), [V8.D2, V9.D2]
	VLD1.P	32(R0), [V10.D2, V11.D2]
	VLD1.P	32(R0), [V12.D2, V13.D2]
	VLD1.P	32(R0), [V14.D2, V15.D2]
	VLD1.P	32(R0), [V16.D2, V17.D2]
	VLD1.P	32(R0), [V18.D2, V19.D2]
	VLD1.P	32(R0), [V20.D2, V21.D2]
	VLD1.P	32(R0), [V22.D2, V23.D2]
	VLD1	(R0), [V24.D2]

	SUB	$384, R0, R0

loop_x2:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x2

	// Store lane-major state.
	VST1.P	[V0.D2, V1.D2], 32(R0)
	VST1.P	[V2.D2, V3.D2], 32(R0)
	VST1.P	[V4.D2, V5.D2], 32(R0)
	VST1.P	[V6.D2, V7.D2], 32(R0)
	VST1.P	[V8.D2, V9.D2], 32(R0)
	VST1.P	[V10.D2, V11.D2], 32(R0)
	VST1.P	[V12.D2, V13.D2], 32(R0)
	VST1.P	[V14.D2, V15.D2], 32(R0)
	VST1.P	[V16.D2, V17.D2], 32(R0)
	VST1.P	[V18.D2, V19.D2], 32(R0)
	VST1.P	[V20.D2, V21.D2], 32(R0)
	VST1.P	[V22.D2, V23.D2], 32(R0)
	VST1	[V24.D2], (R0)

	RET

// func fastLoopAbsorb168x4(s *State4, in *byte, stride, n int)
TEXT ·fastLoopAbsorb168x4(SB), NOSPLIT, $32-32
	MOVD	s+0(FP), R0
	MOVD	in+8(FP), R2
	MOVD	stride+16(FP), R7
	MOVD	n+24(FP), R4

	// Compute 4 pointers: R2=in, R3=in+stride, R5=in+2*stride, R6=in+3*stride.
	ADD	R2, R7, R3
	ADD	R7, R3, R5
	ADD	R7, R5, R6

	// Save in2/in3 and n to stack frame for use between pairs.
	MOVD	R5, 0(RSP)
	MOVD	R6, 8(RSP)
	MOVD	R4, 16(RSP)

	// Pair (0,1): offset 0, stride 32.
	MOVD	R0, R7
	LOAD25_STRIDE(R7, 32)

loop_x4_01:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x4_01

	MOVD	R0, R7
	STORE25_STRIDE(R7, 32)

	// Pair (2,3): offset 16, stride 32.
	MOVD	0(RSP), R2   // in2
	MOVD	8(RSP), R3   // in3
	MOVD	16(RSP), R4  // n

	ADD	$16, R0, R7
	LOAD25_STRIDE(R7, 32)

loop_x4_23:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x4_23

	ADD	$16, R0, R7
	STORE25_STRIDE(R7, 32)

	RET

// func fastLoopAbsorb168x8(s *State8, in *byte, stride, n int)
TEXT ·fastLoopAbsorb168x8(SB), NOSPLIT, $64-32
	MOVD	s+0(FP), R0
	MOVD	in+8(FP), R2
	MOVD	stride+16(FP), R7
	MOVD	n+24(FP), R4

	// Compute 8 pointers from base + i*stride.
	ADD	R2, R7, R3   // in + stride
	ADD	R7, R3, R5   // in + 2*stride
	ADD	R7, R5, R6   // in + 3*stride
	MOVD	R5, 0(RSP)
	MOVD	R6, 8(RSP)
	ADD	R7, R6, R5   // in + 4*stride
	MOVD	R5, 16(RSP)
	ADD	R7, R5, R5   // in + 5*stride
	MOVD	R5, 24(RSP)
	ADD	R7, R5, R5   // in + 6*stride
	MOVD	R5, 32(RSP)
	ADD	R7, R5, R5   // in + 7*stride
	MOVD	R5, 40(RSP)
	MOVD	R4, 48(RSP)

	// Pair (0,1): offset 0, stride 64.
	MOVD	R0, R7
	LOAD25_STRIDE(R7, 64)

loop_x8_01:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x8_01

	MOVD	R0, R7
	STORE25_STRIDE(R7, 64)

	// Pair (2,3): offset 16, stride 64.
	MOVD	0(RSP), R2   // in2
	MOVD	8(RSP), R3   // in3
	MOVD	48(RSP), R4  // n

	ADD	$16, R0, R7
	LOAD25_STRIDE(R7, 64)

loop_x8_23:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x8_23

	ADD	$16, R0, R7
	STORE25_STRIDE(R7, 64)

	// Pair (4,5): offset 32, stride 64.
	MOVD	16(RSP), R2  // in4
	MOVD	24(RSP), R3  // in5
	MOVD	48(RSP), R4  // n

	ADD	$32, R0, R7
	LOAD25_STRIDE(R7, 64)

loop_x8_45:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x8_45

	ADD	$32, R0, R7
	STORE25_STRIDE(R7, 64)

	// Pair (6,7): offset 48, stride 64.
	MOVD	32(RSP), R2  // in6
	MOVD	40(RSP), R3  // in7
	MOVD	48(RSP), R4  // n

	ADD	$48, R0, R7
	LOAD25_STRIDE(R7, 64)

loop_x8_67:
	ABSORB_STRIPE_X2(R2, R3)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x8_67

	ADD	$48, R0, R7
	STORE25_STRIDE(R7, 64)

	RET

// func fastLoopAbsorb168x1(s *State1, in *byte, n int)
TEXT ·fastLoopAbsorb168x1(SB), NOSPLIT, $0-24
	MOVD	s+0(FP), R0
	MOVD	in+8(FP), R2
	MOVD	n+16(FP), R4

	// Load single state (.D1).
	VLD1.P	32(R0), [V0.D1, V1.D1, V2.D1, V3.D1]
	VLD1.P	32(R0), [V4.D1, V5.D1, V6.D1, V7.D1]
	VLD1.P	32(R0), [V8.D1, V9.D1, V10.D1, V11.D1]
	VLD1.P	32(R0), [V12.D1, V13.D1, V14.D1, V15.D1]
	VLD1.P	32(R0), [V16.D1, V17.D1, V18.D1, V19.D1]
	VLD1.P	32(R0), [V20.D1, V21.D1, V22.D1, V23.D1]
	VLD1	(R0), [V24.D1]

	SUB	$192, R0, R0

loop_x1:
	ABSORB_STRIPE_X1(R2)

	MOVD	$round_consts(SB), R1
	ADD	$96, R1
	KECCAK_12_ROUNDS

	SUBS	$168, R4
	BNE	loop_x1

	// Store single state (.D1).
	VST1.P	[V0.D1, V1.D1, V2.D1, V3.D1], 32(R0)
	VST1.P	[V4.D1, V5.D1, V6.D1, V7.D1], 32(R0)
	VST1.P	[V8.D1, V9.D1, V10.D1, V11.D1], 32(R0)
	VST1.P	[V12.D1, V13.D1, V14.D1, V15.D1], 32(R0)
	VST1.P	[V16.D1, V17.D1, V18.D1, V19.D1], 32(R0)
	VST1.P	[V20.D1, V21.D1, V22.D1, V23.D1], 32(R0)
	VST1	[V24.D1], (R0)

	RET
