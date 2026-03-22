//go:build arm64 && !purego

#include "textflag.h"

// func cntvct() uint64
TEXT ·cntvct(SB), NOSPLIT, $0-8
	ISB	$15
	WORD	$0xd53be040 // MRS CNTVCT_EL0, R0
	MOVD	R0, ret+0(FP)
	RET

// func cntfrq() uint64
TEXT ·cntfrq(SB), NOSPLIT, $0-8
	WORD	$0xd53be000 // MRS CNTFRQ_EL0, R0
	MOVD	R0, ret+0(FP)
	RET
