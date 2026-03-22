// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego


#include "textflag.h"
#include "../keccak/permute_amd64_gp.h"
#include "../keccak/permute_amd64_avx512.h"


// func p1600(a *State1)
TEXT ·p1600(SB), $200-8
	MOVQ a+0(FP), DI

	// Convert the user state into an internal state
	NOTQ 8(DI)
	NOTQ 16(DI)
	NOTQ 64(DI)
	NOTQ 96(DI)
	NOTQ 136(DI)
	NOTQ 160(DI)

	// Execute the KeccakF permutation
	MOVQ (DI), SI
	MOVQ 8(DI), BP
	MOVQ 32(DI), R15
	XORQ 40(DI), SI
	XORQ 48(DI), BP
	XORQ 72(DI), R15
	XORQ 80(DI), SI
	XORQ 88(DI), BP
	XORQ 112(DI), R15
	XORQ 120(DI), SI
	XORQ 128(DI), BP
	XORQ 152(DI), R15
	XORQ 160(DI), SI
	XORQ 168(DI), BP
	MOVQ 176(DI), DX
	MOVQ 184(DI), R8
	XORQ 192(DI), R15

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

	// Revert the internal state to the user state
	NOTQ 8(DI)
	NOTQ 16(DI)
	NOTQ 64(DI)
	NOTQ 96(DI)
	NOTQ 136(DI)
	NOTQ 160(DI)
	RET

// AVX-512 x1 permutation constants (1280 bytes = 20 × 64).
// Layout documented in keccak_amd64_avx512.h.

// theta_perm[0]: identity (not loaded, but occupies space)
DATA	tw128_avx512_x1_consts+0x000(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x008(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x010(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x018(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x020(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x028(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x030(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x038(SB)/8, $7
// theta_perm[1] → Z13
DATA	tw128_avx512_x1_consts+0x040(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x048(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x050(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x058(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x060(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x068(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x070(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x078(SB)/8, $7
// theta_perm[2] → Z14
DATA	tw128_avx512_x1_consts+0x080(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x088(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x090(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x098(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x0A0(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x0A8(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x0B0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x0B8(SB)/8, $7
// theta_perm[3] → Z15
DATA	tw128_avx512_x1_consts+0x0C0(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x0C8(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x0D0(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x0D8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x0E0(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x0E8(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x0F0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x0F8(SB)/8, $7
// theta_perm[4] → Z16
DATA	tw128_avx512_x1_consts+0x100(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x108(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x110(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x118(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x120(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x128(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x130(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x138(SB)/8, $7
// rhotates1[0] → Z27
DATA	tw128_avx512_x1_consts+0x140(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x148(SB)/8, $44
DATA	tw128_avx512_x1_consts+0x150(SB)/8, $43
DATA	tw128_avx512_x1_consts+0x158(SB)/8, $21
DATA	tw128_avx512_x1_consts+0x160(SB)/8, $14
DATA	tw128_avx512_x1_consts+0x168(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x170(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x178(SB)/8, $0
// rhotates1[1] → Z28
DATA	tw128_avx512_x1_consts+0x180(SB)/8, $18
DATA	tw128_avx512_x1_consts+0x188(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x190(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x198(SB)/8, $25
DATA	tw128_avx512_x1_consts+0x1A0(SB)/8, $8
DATA	tw128_avx512_x1_consts+0x1A8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x1B0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x1B8(SB)/8, $0
// rhotates1[2] → Z29
DATA	tw128_avx512_x1_consts+0x1C0(SB)/8, $41
DATA	tw128_avx512_x1_consts+0x1C8(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x1D0(SB)/8, $62
DATA	tw128_avx512_x1_consts+0x1D8(SB)/8, $55
DATA	tw128_avx512_x1_consts+0x1E0(SB)/8, $39
DATA	tw128_avx512_x1_consts+0x1E8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x1F0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x1F8(SB)/8, $0
// rhotates1[3] → Z30
DATA	tw128_avx512_x1_consts+0x200(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x208(SB)/8, $45
DATA	tw128_avx512_x1_consts+0x210(SB)/8, $61
DATA	tw128_avx512_x1_consts+0x218(SB)/8, $28
DATA	tw128_avx512_x1_consts+0x220(SB)/8, $20
DATA	tw128_avx512_x1_consts+0x228(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x230(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x238(SB)/8, $0
// rhotates1[4] → Z31
DATA	tw128_avx512_x1_consts+0x240(SB)/8, $36
DATA	tw128_avx512_x1_consts+0x248(SB)/8, $10
DATA	tw128_avx512_x1_consts+0x250(SB)/8, $15
DATA	tw128_avx512_x1_consts+0x258(SB)/8, $56
DATA	tw128_avx512_x1_consts+0x260(SB)/8, $27
DATA	tw128_avx512_x1_consts+0x268(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x270(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x278(SB)/8, $0
// rhotates0[0] → Z22
DATA	tw128_avx512_x1_consts+0x280(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x288(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x290(SB)/8, $62
DATA	tw128_avx512_x1_consts+0x298(SB)/8, $28
DATA	tw128_avx512_x1_consts+0x2A0(SB)/8, $27
DATA	tw128_avx512_x1_consts+0x2A8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x2B0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x2B8(SB)/8, $0
// rhotates0[1] → Z23
DATA	tw128_avx512_x1_consts+0x2C0(SB)/8, $36
DATA	tw128_avx512_x1_consts+0x2C8(SB)/8, $44
DATA	tw128_avx512_x1_consts+0x2D0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x2D8(SB)/8, $55
DATA	tw128_avx512_x1_consts+0x2E0(SB)/8, $20
DATA	tw128_avx512_x1_consts+0x2E8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x2F0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x2F8(SB)/8, $0
// rhotates0[2] → Z24
DATA	tw128_avx512_x1_consts+0x300(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x308(SB)/8, $10
DATA	tw128_avx512_x1_consts+0x310(SB)/8, $43
DATA	tw128_avx512_x1_consts+0x318(SB)/8, $25
DATA	tw128_avx512_x1_consts+0x320(SB)/8, $39
DATA	tw128_avx512_x1_consts+0x328(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x330(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x338(SB)/8, $0
// rhotates0[3] → Z25
DATA	tw128_avx512_x1_consts+0x340(SB)/8, $41
DATA	tw128_avx512_x1_consts+0x348(SB)/8, $45
DATA	tw128_avx512_x1_consts+0x350(SB)/8, $15
DATA	tw128_avx512_x1_consts+0x358(SB)/8, $21
DATA	tw128_avx512_x1_consts+0x360(SB)/8, $8
DATA	tw128_avx512_x1_consts+0x368(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x370(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x378(SB)/8, $0
// rhotates0[4] → Z26
DATA	tw128_avx512_x1_consts+0x380(SB)/8, $18
DATA	tw128_avx512_x1_consts+0x388(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x390(SB)/8, $61
DATA	tw128_avx512_x1_consts+0x398(SB)/8, $56
DATA	tw128_avx512_x1_consts+0x3A0(SB)/8, $14
DATA	tw128_avx512_x1_consts+0x3A8(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x3B0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x3B8(SB)/8, $0
// pi0_perm[0] → Z17
DATA	tw128_avx512_x1_consts+0x3C0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x3C8(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x3D0(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x3D8(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x3E0(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x3E8(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x3F0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x3F8(SB)/8, $7
// pi0_perm[1] → Z18
DATA	tw128_avx512_x1_consts+0x400(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x408(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x410(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x418(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x420(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x428(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x430(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x438(SB)/8, $7
// pi0_perm[2] → Z19
DATA	tw128_avx512_x1_consts+0x440(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x448(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x450(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x458(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x460(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x468(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x470(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x478(SB)/8, $7
// pi0_perm[3] → Z20
DATA	tw128_avx512_x1_consts+0x480(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x488(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x490(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x498(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x4A0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x4A8(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x4B0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x4B8(SB)/8, $7
// pi0_perm[4] → Z21
DATA	tw128_avx512_x1_consts+0x4C0(SB)/8, $4
DATA	tw128_avx512_x1_consts+0x4C8(SB)/8, $2
DATA	tw128_avx512_x1_consts+0x4D0(SB)/8, $0
DATA	tw128_avx512_x1_consts+0x4D8(SB)/8, $3
DATA	tw128_avx512_x1_consts+0x4E0(SB)/8, $1
DATA	tw128_avx512_x1_consts+0x4E8(SB)/8, $5
DATA	tw128_avx512_x1_consts+0x4F0(SB)/8, $6
DATA	tw128_avx512_x1_consts+0x4F8(SB)/8, $7
GLOBL	tw128_avx512_x1_consts(SB), NOPTR|RODATA, $1280

// AVX-512 x1 round constants (all 24 rounds + 8 zero padding = 256 bytes).
// For 12-round Keccak-p[1600,12], R10 points to offset 96 (round 12).
DATA	tw128_avx512_x1_iotas+0x00(SB)/8, $0x0000000000000001
DATA	tw128_avx512_x1_iotas+0x08(SB)/8, $0x0000000000008082
DATA	tw128_avx512_x1_iotas+0x10(SB)/8, $0x800000000000808a
DATA	tw128_avx512_x1_iotas+0x18(SB)/8, $0x8000000080008000
DATA	tw128_avx512_x1_iotas+0x20(SB)/8, $0x000000000000808b
DATA	tw128_avx512_x1_iotas+0x28(SB)/8, $0x0000000080000001
DATA	tw128_avx512_x1_iotas+0x30(SB)/8, $0x8000000080008081
DATA	tw128_avx512_x1_iotas+0x38(SB)/8, $0x8000000000008009
DATA	tw128_avx512_x1_iotas+0x40(SB)/8, $0x000000000000008a
DATA	tw128_avx512_x1_iotas+0x48(SB)/8, $0x0000000000000088
DATA	tw128_avx512_x1_iotas+0x50(SB)/8, $0x0000000080008009
DATA	tw128_avx512_x1_iotas+0x58(SB)/8, $0x000000008000000a
DATA	tw128_avx512_x1_iotas+0x60(SB)/8, $0x000000008000808b
DATA	tw128_avx512_x1_iotas+0x68(SB)/8, $0x800000000000008b
DATA	tw128_avx512_x1_iotas+0x70(SB)/8, $0x8000000000008089
DATA	tw128_avx512_x1_iotas+0x78(SB)/8, $0x8000000000008003
DATA	tw128_avx512_x1_iotas+0x80(SB)/8, $0x8000000000008002
DATA	tw128_avx512_x1_iotas+0x88(SB)/8, $0x8000000000000080
DATA	tw128_avx512_x1_iotas+0x90(SB)/8, $0x000000000000800a
DATA	tw128_avx512_x1_iotas+0x98(SB)/8, $0x800000008000000a
DATA	tw128_avx512_x1_iotas+0xA0(SB)/8, $0x8000000080008081
DATA	tw128_avx512_x1_iotas+0xA8(SB)/8, $0x8000000000008080
DATA	tw128_avx512_x1_iotas+0xB0(SB)/8, $0x0000000080000001
DATA	tw128_avx512_x1_iotas+0xB8(SB)/8, $0x8000000080008008
DATA	tw128_avx512_x1_iotas+0xC0(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xC8(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xD0(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xD8(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xE0(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xE8(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xF0(SB)/8, $0
DATA	tw128_avx512_x1_iotas+0xF8(SB)/8, $0
GLOBL	tw128_avx512_x1_iotas(SB), NOPTR|RODATA, $256


// func p1600AVX512(a *State1)
//
// AVX-512 x1 Keccak-p[1600,12] permutation using Andy Polyakov's CRYPTOGAMS
// approach: state in 5 ZMM registers, alternating even/odd round layouts.
TEXT ·p1600AVX512(SB), $0-8
	MOVQ	a+0(FP), DI

	// Setup masks and load constants.
	X1_SETUP_MASKS
	LEAQ	tw128_avx512_x1_consts(SB), R8
	X1_LOAD_CONSTS

	// Load state.
	X1_LOAD_STATE

	// 12 rounds = 6 iterations × 2 rounds.
	LEAQ	tw128_avx512_x1_iotas+96(SB), R10
	MOVL	$6, AX

	PCALIGN	$32
p1600avx512_loop:
	X1_EVEN_ROUND
	X1_ODD_ROUND
	DECL	AX
	JNZ	p1600avx512_loop

	// Store state.
	X1_STORE_STATE
	VZEROUPPER
	RET
