//go:build !purego

#include "textflag.h"
#include "../keccak/permute_arm64.h"

// func p1600x8Lane(a *state8)
TEXT ·p1600x8Lane(SB), NOSPLIT, $0-8
	MOVD	a+0(FP), R0

	// Pair (0,1): offset 0, stride 64 bytes per lane.
	MOVD	R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	MOVD	R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (2,3): offset 16, stride 64 bytes per lane.
	ADD	$16, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$16, R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (4,5): offset 32, stride 64 bytes per lane.
	ADD	$32, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$32, R0, R2
	STORE25_STRIDE(R2, 64)

	// Pair (6,7): offset 48, stride 64 bytes per lane.
	ADD	$48, R0, R2
	MOVD	$tw128_round_consts(SB), R1
	ADD	$96, R1
	LOAD25_STRIDE(R2, 64)
	KECCAK_12_ROUNDS
	ADD	$48, R0, R2
	STORE25_STRIDE(R2, 64)

	RET
