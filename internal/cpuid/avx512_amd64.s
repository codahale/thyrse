//go:build amd64 && !purego && !thyrse_disable_avx512

#include "textflag.h"

// func hasAVX512VL() bool
TEXT ·hasAVX512VL(SB), NOSPLIT, $0-1
	// Check OSXSAVE (CPUID.1:ECX bit 27) so XGETBV is usable.
	MOVL	$1, AX
	XORL	CX, CX
	CPUID
	BTL	$27, CX
	JCC	no

	// Check XCR0: OS saves YMM (bit 2) and ZMM (bits 5,6,7).
	XORL	CX, CX
	XGETBV
	ANDL	$0xE4, AX
	CMPL	AX, $0xE4
	JNE	no

	// Check AVX512F (leaf 7, EBX bit 16) and AVX512VL (EBX bit 31).
	MOVL	$7, AX
	XORL	CX, CX
	CPUID
	BTL	$16, BX
	JCC	no
	BTL	$31, BX
	JCC	no

	MOVB	$1, ret+0(FP)
	RET

no:
	MOVB	$0, ret+0(FP)
	RET
