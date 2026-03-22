// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

#include "textflag.h"
#include "../keccak/permute_arm64.h"

// func p1600(a *State1)
TEXT ·p1600(SB), $200-8
	MOVD	a+0(FP), R0
	MOVD	$kt128_round_consts(SB), R1
	ADD	$96, R1

	VLD1.P	32(R0), [V0.D1, V1.D1, V2.D1, V3.D1]
	VLD1.P	32(R0), [V4.D1, V5.D1, V6.D1, V7.D1]
	VLD1.P	32(R0), [V8.D1, V9.D1, V10.D1, V11.D1]
	VLD1.P	32(R0), [V12.D1, V13.D1, V14.D1, V15.D1]
	VLD1.P	32(R0), [V16.D1, V17.D1, V18.D1, V19.D1]
	VLD1.P	32(R0), [V20.D1, V21.D1, V22.D1, V23.D1]
	VLD1	(R0), [V24.D1]

	SUB	$192, R0, R0

	KECCAK_12_ROUNDS

	VST1.P	[V0.D1, V1.D1, V2.D1, V3.D1], 32(R0)
	VST1.P	[V4.D1, V5.D1, V6.D1, V7.D1], 32(R0)
	VST1.P	[V8.D1, V9.D1, V10.D1, V11.D1], 32(R0)
	VST1.P	[V12.D1, V13.D1, V14.D1, V15.D1], 32(R0)
	VST1.P	[V16.D1, V17.D1, V18.D1, V19.D1], 32(R0)
	VST1.P	[V20.D1, V21.D1, V22.D1, V23.D1], 32(R0)
	VST1	[V24.D1], (R0)

	RET



// func p1600x2Lane(a *[Lanes][2]uint64)
TEXT ·p1600x2Lane(SB), NOSPLIT, $0-8
	MOVD	a+0(FP), R0
	MOVD	$kt128_round_consts(SB), R1
	ADD	$96, R1 // start at round 12

	// Load lane-major packed state: each lane is a 128-bit {inst0, inst1} vector.
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

	KECCAK_12_ROUNDS

	// Store lane-major packed state.
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
