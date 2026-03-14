// Fused KT128 leaf processing — AVX-512 and AVX2 implementations.
//
// Each function processes 8 × 8192-byte chunks in a single call,
// producing 8 × 32-byte chain values without materializing intermediate state.

//go:build !purego

#include "textflag.h"
#include "permute_amd64_avx2.h"
#include "permute_amd64_avx512.h"

// ABSORB_LANE_X8_GATHER gathers one uint64 from 8 instances at the given byte
// offset from BX (data base pointer) using Z28 as the index vector
// ({0, stride, 2*stride, ..., 7*stride}), and XORs the result into Zlane.
// K1 is reset to all-ones before each gather.
#define ABSORB_LANE_X8_GATHER(offset, Zlane) \
	KXNORB	K1, K1, K1; \
	VPGATHERQQ	offset(BX)(Z28*1), K1, Z25; \
	VPXORQ	Z25, Zlane, Zlane

// VPBROADCASTQ_IMM_0x0B broadcasts 0x0B to all 8 qwords in Zdst.
#define VPBROADCASTQ_IMM_0x0B(Zdst) \
	MOVQ	$0x0B, AX; \
	VPBROADCASTQ	AX, Zdst

// VPBROADCASTQ_IMM_0x80_HIGH broadcasts 0x8000000000000000 to all 8 qwords in Zdst.
#define VPBROADCASTQ_IMM_0x80_HIGH(Zdst) \
	MOVQ	$0x8000000000000000, AX; \
	VPBROADCASTQ	AX, Zdst

// func processLeavesKT128AVX512(input *byte, cvs *byte)
//
// Processes 8 × 8192-byte chunks, writing 8 × 32-byte CVs to cvs.
// Input: 8 contiguous 8192-byte blocks (total 65536 bytes).
//
// KT128 leaf constants (hardcoded):
//   Rate = 168, DS = 0x0B, BlockSize = 8192
//   48 full 168-byte stripes per 8192-byte chunk
//   128-byte remainder = 16 lanes
//   Suffix 0x0B at lane 16, pad10*1 end 0x80 at lane 20
//
// Frame: 64 bytes local (gather indices), 16 bytes args.
// Register allocation:
//   BX   = data base pointer
//   R11  = round constants pointer
//   R12  = stripe loop counter
//   Z0-Z24  = Keccak state (persistent)
//   Z25-Z31 = scratch
//   Z28     = gather index vector
TEXT ·processLeavesKT128AVX512(SB), $64-16
	MOVQ	input+0(FP), BX
	MOVQ	cvs+8(FP), DI

	// Build gather index vector {0, 8192, 2×8192, ..., 7×8192} at SP+0.
	MOVQ	$0, 0(SP)
	MOVQ	$8192, 8(SP)
	MOVQ	$16384, 16(SP)
	MOVQ	$24576, 24(SP)
	MOVQ	$32768, 32(SP)
	MOVQ	$40960, 40(SP)
	MOVQ	$49152, 48(SP)
	MOVQ	$57344, 56(SP)

	// Zero state Z0-Z24.
	VPXORQ	Z0, Z0, Z0
	VPXORQ	Z1, Z1, Z1
	VPXORQ	Z2, Z2, Z2
	VPXORQ	Z3, Z3, Z3
	VPXORQ	Z4, Z4, Z4
	VPXORQ	Z5, Z5, Z5
	VPXORQ	Z6, Z6, Z6
	VPXORQ	Z7, Z7, Z7
	VPXORQ	Z8, Z8, Z8
	VPXORQ	Z9, Z9, Z9
	VPXORQ	Z10, Z10, Z10
	VPXORQ	Z11, Z11, Z11
	VPXORQ	Z12, Z12, Z12
	VPXORQ	Z13, Z13, Z13
	VPXORQ	Z14, Z14, Z14
	VPXORQ	Z15, Z15, Z15
	VPXORQ	Z16, Z16, Z16
	VPXORQ	Z17, Z17, Z17
	VPXORQ	Z18, Z18, Z18
	VPXORQ	Z19, Z19, Z19
	VPXORQ	Z20, Z20, Z20
	VPXORQ	Z21, Z21, Z21
	VPXORQ	Z22, Z22, Z22
	VPXORQ	Z23, Z23, Z23
	VPXORQ	Z24, Z24, Z24

	// Loop 48 full stripes.
	MOVQ	$48, R12

leaves_avx512_loop:
	// Reload gather index vector (Z28 is clobbered by permutation).
	VMOVDQU64	0(SP), Z28

	// Absorb 21 rate lanes via gather.
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

	// Permute: 12 rounds = 3 × 4 rounds.
	LEAQ	round_consts_2x+192(SB), R11
	X8_4ROUNDS_AVX512(0, 16, 32, 48)
	X8_4ROUNDS_AVX512(64, 80, 96, 112)
	X8_4ROUNDS_AVX512(128, 144, 160, 176)

	// Advance data pointer by 168 bytes.
	ADDQ	$168, BX
	SUBQ	$1, R12
	JNZ	leaves_avx512_loop

	// Absorb final 16 lanes (128-byte remainder).
	VMOVDQU64	0(SP), Z28
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

	// XOR padding: DS=0x0B into lane 16, pad10*1 end 0x80 into lane 20.
	VPBROADCASTQ_IMM_0x0B(Z25)
	VPXORQ	Z25, Z16, Z16
	VPBROADCASTQ_IMM_0x80_HIGH(Z25)
	VPXORQ	Z25, Z20, Z20

	// Final permutation.
	LEAQ	round_consts_2x+192(SB), R11
	X8_4ROUNDS_AVX512(0, 16, 32, 48)
	X8_4ROUNDS_AVX512(64, 80, 96, 112)
	X8_4ROUNDS_AVX512(128, 144, 160, 176)

	// Extract CVs via VPSCATTERQQ.
	MOVQ	$0, 0(SP)
	MOVQ	$32, 8(SP)
	MOVQ	$64, 16(SP)
	MOVQ	$96, 24(SP)
	MOVQ	$128, 32(SP)
	MOVQ	$160, 40(SP)
	MOVQ	$192, 48(SP)
	MOVQ	$224, 56(SP)
	VMOVDQU64	0(SP), Z28

	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z0, K1, 0(DI)(Z28*1)
	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z1, K1, 8(DI)(Z28*1)
	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z2, K1, 16(DI)(Z28*1)
	KXNORB	K1, K1, K1
	VPSCATTERQQ	Z3, K1, 24(DI)(Z28*1)

	VZEROUPPER
	RET


// ABSORB_LANE_X4 XORs lane i from 4 input pointers into the state buffer.
// AX=in0, CX=in1, DX=in2, BX=in3, R8=state buffer.
#define ABSORB_LANE_X4(i) \
	MOVQ	i*8(AX), R10; XORQ	R10, i*32+0(R8); \
	MOVQ	i*8(CX), R10; XORQ	R10, i*32+8(R8); \
	MOVQ	i*8(DX), R10; XORQ	R10, i*32+16(R8); \
	MOVQ	i*8(BX), R10; XORQ	R10, i*32+24(R8)

// func processLeavesKT128AVX2(input *byte, cvs *byte)
//
// Processes 8 × 8192-byte chunks via 2× x4 AVX2, writing 8 × 32-byte CVs.
//
// Frame: 1648 bytes local (0-799 = buffer A, 800-1599 = buffer B,
//        1600-1647 = 4 input ptrs + count + saved output ptr), 16 bytes args.
TEXT ·processLeavesKT128AVX2(SB), $1648-16
	MOVQ	input+0(FP), AX
	MOVQ	cvs+8(FP), DI
	MOVQ	DI, 1640(SP)		// save output pointer

	// === Half 0: instances 0-3 ===
	// Input pointers: in + {0, 1, 2, 3}×8192.
	MOVQ	AX, 1600(SP)		// in0
	LEAQ	8192(AX), R10
	MOVQ	R10, 1608(SP)		// in1
	LEAQ	8192(R10), R10
	MOVQ	R10, 1616(SP)		// in2
	LEAQ	8192(R10), R10
	MOVQ	R10, 1624(SP)		// in3
	MOVQ	$48, 1632(SP)		// stripe count

	// Zero buffer A (25 lanes × 32 bytes = 800 bytes).
	VPXOR	Y0, Y0, Y0
	VMOVDQU	Y0, 0*32(SP)
	VMOVDQU	Y0, 1*32(SP)
	VMOVDQU	Y0, 2*32(SP)
	VMOVDQU	Y0, 3*32(SP)
	VMOVDQU	Y0, 4*32(SP)
	VMOVDQU	Y0, 5*32(SP)
	VMOVDQU	Y0, 6*32(SP)
	VMOVDQU	Y0, 7*32(SP)
	VMOVDQU	Y0, 8*32(SP)
	VMOVDQU	Y0, 9*32(SP)
	VMOVDQU	Y0, 10*32(SP)
	VMOVDQU	Y0, 11*32(SP)
	VMOVDQU	Y0, 12*32(SP)
	VMOVDQU	Y0, 13*32(SP)
	VMOVDQU	Y0, 14*32(SP)
	VMOVDQU	Y0, 15*32(SP)
	VMOVDQU	Y0, 16*32(SP)
	VMOVDQU	Y0, 17*32(SP)
	VMOVDQU	Y0, 18*32(SP)
	VMOVDQU	Y0, 19*32(SP)
	VMOVDQU	Y0, 20*32(SP)
	VMOVDQU	Y0, 21*32(SP)
	VMOVDQU	Y0, 22*32(SP)
	VMOVDQU	Y0, 23*32(SP)
	VMOVDQU	Y0, 24*32(SP)

leaves_avx2_loop_a:
	CMPQ	1632(SP), $0
	JEQ	leaves_avx2_final_a

	// Absorb from instances 0-3.
	LEAQ	0(SP), R8
	MOVQ	1600(SP), AX
	MOVQ	1608(SP), CX
	MOVQ	1616(SP), DX
	MOVQ	1624(SP), BX

	ABSORB_LANE_X4(0)
	ABSORB_LANE_X4(1)
	ABSORB_LANE_X4(2)
	ABSORB_LANE_X4(3)
	ABSORB_LANE_X4(4)
	ABSORB_LANE_X4(5)
	ABSORB_LANE_X4(6)
	ABSORB_LANE_X4(7)
	ABSORB_LANE_X4(8)
	ABSORB_LANE_X4(9)
	ABSORB_LANE_X4(10)
	ABSORB_LANE_X4(11)
	ABSORB_LANE_X4(12)
	ABSORB_LANE_X4(13)
	ABSORB_LANE_X4(14)
	ABSORB_LANE_X4(15)
	ABSORB_LANE_X4(16)
	ABSORB_LANE_X4(17)
	ABSORB_LANE_X4(18)
	ABSORB_LANE_X4(19)
	ABSORB_LANE_X4(20)

	ADDQ	$168, AX
	ADDQ	$168, CX
	ADDQ	$168, DX
	ADDQ	$168, BX
	MOVQ	AX, 1600(SP)
	MOVQ	CX, 1608(SP)
	MOVQ	DX, 1616(SP)
	MOVQ	BX, 1624(SP)
	SUBQ	$1, 1632(SP)

	// Permute.
	LEAQ	0(SP), R8
	LEAQ	800(SP), R9
	LEAQ	round_consts_4x+384(SB), R11
	MOVQ	$12, R10

	PCALIGN	$16
leaves_avx2_round_a:
	X4_KECCAK_ROUND
	XCHGQ	R8, R9
	ADDQ	$32, R11
	SUBQ	$1, R10
	JNZ	leaves_avx2_round_a

	JMP	leaves_avx2_loop_a

leaves_avx2_final_a:
	// Absorb final 16 lanes from instances 0-3.
	LEAQ	0(SP), R8
	MOVQ	1600(SP), AX
	MOVQ	1608(SP), CX
	MOVQ	1616(SP), DX
	MOVQ	1624(SP), BX

	ABSORB_LANE_X4(0)
	ABSORB_LANE_X4(1)
	ABSORB_LANE_X4(2)
	ABSORB_LANE_X4(3)
	ABSORB_LANE_X4(4)
	ABSORB_LANE_X4(5)
	ABSORB_LANE_X4(6)
	ABSORB_LANE_X4(7)
	ABSORB_LANE_X4(8)
	ABSORB_LANE_X4(9)
	ABSORB_LANE_X4(10)
	ABSORB_LANE_X4(11)
	ABSORB_LANE_X4(12)
	ABSORB_LANE_X4(13)
	ABSORB_LANE_X4(14)
	ABSORB_LANE_X4(15)

	// XOR padding: DS=0x0B into lane 16 (all 4 instances), pad end into lane 20.
	LEAQ	0(SP), R8
	MOVQ	$0x0B, R10
	XORQ	R10, 16*32+0(R8)
	XORQ	R10, 16*32+8(R8)
	XORQ	R10, 16*32+16(R8)
	XORQ	R10, 16*32+24(R8)
	MOVQ	$0x8000000000000000, R10
	XORQ	R10, 20*32+0(R8)
	XORQ	R10, 20*32+8(R8)
	XORQ	R10, 20*32+16(R8)
	XORQ	R10, 20*32+24(R8)

	// Final permutation.
	LEAQ	0(SP), R8
	LEAQ	800(SP), R9
	LEAQ	round_consts_4x+384(SB), R11
	MOVQ	$12, R10

	PCALIGN	$16
leaves_avx2_final_round_a:
	X4_KECCAK_ROUND
	XCHGQ	R8, R9
	ADDQ	$32, R11
	SUBQ	$1, R10
	JNZ	leaves_avx2_final_round_a

	// Extract CVs for instances 0-3 via UNPACK+PERM128 transpose.
	MOVQ	1640(SP), DI
	LEAQ	0(SP), R8

	VMOVDQU	0*32(R8), Y0	// lane 0: {i0, i1, i2, i3}
	VMOVDQU	1*32(R8), Y1	// lane 1
	VMOVDQU	2*32(R8), Y2	// lane 2
	VMOVDQU	3*32(R8), Y3	// lane 3

	VPUNPCKLQDQ	Y1, Y0, Y4	// {i0_l0, i0_l1, i2_l0, i2_l1}
	VPUNPCKHQDQ	Y1, Y0, Y5	// {i1_l0, i1_l1, i3_l0, i3_l1}
	VPUNPCKLQDQ	Y3, Y2, Y6	// {i0_l2, i0_l3, i2_l2, i2_l3}
	VPUNPCKHQDQ	Y3, Y2, Y7	// {i1_l2, i1_l3, i3_l2, i3_l3}

	VPERM2F128	$0x20, Y6, Y4, Y0	// inst0 CV
	VPERM2F128	$0x20, Y7, Y5, Y1	// inst1 CV
	VPERM2F128	$0x31, Y6, Y4, Y2	// inst2 CV
	VPERM2F128	$0x31, Y7, Y5, Y3	// inst3 CV

	VMOVDQU	Y0, 0*32(DI)
	VMOVDQU	Y1, 1*32(DI)
	VMOVDQU	Y2, 2*32(DI)
	VMOVDQU	Y3, 3*32(DI)

	// === Half 1: instances 4-7 ===
	MOVQ	input+0(FP), AX
	LEAQ	32768(AX), AX		// in + 4×8192
	MOVQ	AX, 1600(SP)		// in4
	LEAQ	8192(AX), R10
	MOVQ	R10, 1608(SP)		// in5
	LEAQ	8192(R10), R10
	MOVQ	R10, 1616(SP)		// in6
	LEAQ	8192(R10), R10
	MOVQ	R10, 1624(SP)		// in7
	MOVQ	$48, 1632(SP)		// stripe count

	// Zero buffer A.
	VPXOR	Y0, Y0, Y0
	VMOVDQU	Y0, 0*32(SP)
	VMOVDQU	Y0, 1*32(SP)
	VMOVDQU	Y0, 2*32(SP)
	VMOVDQU	Y0, 3*32(SP)
	VMOVDQU	Y0, 4*32(SP)
	VMOVDQU	Y0, 5*32(SP)
	VMOVDQU	Y0, 6*32(SP)
	VMOVDQU	Y0, 7*32(SP)
	VMOVDQU	Y0, 8*32(SP)
	VMOVDQU	Y0, 9*32(SP)
	VMOVDQU	Y0, 10*32(SP)
	VMOVDQU	Y0, 11*32(SP)
	VMOVDQU	Y0, 12*32(SP)
	VMOVDQU	Y0, 13*32(SP)
	VMOVDQU	Y0, 14*32(SP)
	VMOVDQU	Y0, 15*32(SP)
	VMOVDQU	Y0, 16*32(SP)
	VMOVDQU	Y0, 17*32(SP)
	VMOVDQU	Y0, 18*32(SP)
	VMOVDQU	Y0, 19*32(SP)
	VMOVDQU	Y0, 20*32(SP)
	VMOVDQU	Y0, 21*32(SP)
	VMOVDQU	Y0, 22*32(SP)
	VMOVDQU	Y0, 23*32(SP)
	VMOVDQU	Y0, 24*32(SP)

leaves_avx2_loop_b:
	CMPQ	1632(SP), $0
	JEQ	leaves_avx2_final_b

	LEAQ	0(SP), R8
	MOVQ	1600(SP), AX
	MOVQ	1608(SP), CX
	MOVQ	1616(SP), DX
	MOVQ	1624(SP), BX

	ABSORB_LANE_X4(0)
	ABSORB_LANE_X4(1)
	ABSORB_LANE_X4(2)
	ABSORB_LANE_X4(3)
	ABSORB_LANE_X4(4)
	ABSORB_LANE_X4(5)
	ABSORB_LANE_X4(6)
	ABSORB_LANE_X4(7)
	ABSORB_LANE_X4(8)
	ABSORB_LANE_X4(9)
	ABSORB_LANE_X4(10)
	ABSORB_LANE_X4(11)
	ABSORB_LANE_X4(12)
	ABSORB_LANE_X4(13)
	ABSORB_LANE_X4(14)
	ABSORB_LANE_X4(15)
	ABSORB_LANE_X4(16)
	ABSORB_LANE_X4(17)
	ABSORB_LANE_X4(18)
	ABSORB_LANE_X4(19)
	ABSORB_LANE_X4(20)

	ADDQ	$168, AX
	ADDQ	$168, CX
	ADDQ	$168, DX
	ADDQ	$168, BX
	MOVQ	AX, 1600(SP)
	MOVQ	CX, 1608(SP)
	MOVQ	DX, 1616(SP)
	MOVQ	BX, 1624(SP)
	SUBQ	$1, 1632(SP)

	LEAQ	0(SP), R8
	LEAQ	800(SP), R9
	LEAQ	round_consts_4x+384(SB), R11
	MOVQ	$12, R10

	PCALIGN	$16
leaves_avx2_round_b:
	X4_KECCAK_ROUND
	XCHGQ	R8, R9
	ADDQ	$32, R11
	SUBQ	$1, R10
	JNZ	leaves_avx2_round_b

	JMP	leaves_avx2_loop_b

leaves_avx2_final_b:
	// Absorb final 16 lanes from instances 4-7.
	LEAQ	0(SP), R8
	MOVQ	1600(SP), AX
	MOVQ	1608(SP), CX
	MOVQ	1616(SP), DX
	MOVQ	1624(SP), BX

	ABSORB_LANE_X4(0)
	ABSORB_LANE_X4(1)
	ABSORB_LANE_X4(2)
	ABSORB_LANE_X4(3)
	ABSORB_LANE_X4(4)
	ABSORB_LANE_X4(5)
	ABSORB_LANE_X4(6)
	ABSORB_LANE_X4(7)
	ABSORB_LANE_X4(8)
	ABSORB_LANE_X4(9)
	ABSORB_LANE_X4(10)
	ABSORB_LANE_X4(11)
	ABSORB_LANE_X4(12)
	ABSORB_LANE_X4(13)
	ABSORB_LANE_X4(14)
	ABSORB_LANE_X4(15)

	// XOR padding.
	LEAQ	0(SP), R8
	MOVQ	$0x0B, R10
	XORQ	R10, 16*32+0(R8)
	XORQ	R10, 16*32+8(R8)
	XORQ	R10, 16*32+16(R8)
	XORQ	R10, 16*32+24(R8)
	MOVQ	$0x8000000000000000, R10
	XORQ	R10, 20*32+0(R8)
	XORQ	R10, 20*32+8(R8)
	XORQ	R10, 20*32+16(R8)
	XORQ	R10, 20*32+24(R8)

	// Final permutation.
	LEAQ	0(SP), R8
	LEAQ	800(SP), R9
	LEAQ	round_consts_4x+384(SB), R11
	MOVQ	$12, R10

	PCALIGN	$16
leaves_avx2_final_round_b:
	X4_KECCAK_ROUND
	XCHGQ	R8, R9
	ADDQ	$32, R11
	SUBQ	$1, R10
	JNZ	leaves_avx2_final_round_b

	// Extract CVs for instances 4-7 via UNPACK+PERM128 transpose.
	MOVQ	1640(SP), DI
	LEAQ	0(SP), R8

	VMOVDQU	0*32(R8), Y0	// lane 0: {i4, i5, i6, i7}
	VMOVDQU	1*32(R8), Y1	// lane 1
	VMOVDQU	2*32(R8), Y2	// lane 2
	VMOVDQU	3*32(R8), Y3	// lane 3

	VPUNPCKLQDQ	Y1, Y0, Y4
	VPUNPCKHQDQ	Y1, Y0, Y5
	VPUNPCKLQDQ	Y3, Y2, Y6
	VPUNPCKHQDQ	Y3, Y2, Y7

	VPERM2F128	$0x20, Y6, Y4, Y0	// inst4 CV
	VPERM2F128	$0x20, Y7, Y5, Y1	// inst5 CV
	VPERM2F128	$0x31, Y6, Y4, Y2	// inst6 CV
	VPERM2F128	$0x31, Y7, Y5, Y3	// inst7 CV

	VMOVDQU	Y0, 4*32(DI)
	VMOVDQU	Y1, 5*32(DI)
	VMOVDQU	Y2, 6*32(DI)
	VMOVDQU	Y3, 7*32(DI)

	VZEROUPPER
	RET
