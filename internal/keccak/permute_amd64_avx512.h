// x8 AVX512 Keccak permutation macros.
// State lives in Z0-Z24 (25 lanes × 8 uint64s per ZMM register).
// Z25-Z31 are scratch.  No stack scratch needed for theta.
// R11 must point to the round constant table.

#define ROT64_AVX512_8X(reg, amount) \
	VPROLQ	$amount, reg, reg

// XOR five lanes into dst: dst = a ^ b ^ c ^ d ^ e.
#define XOR5_AVX512_8X(dst, a, b, c, d, e) \
	VMOVDQU64	a, dst; \
	VPTERNLOGQ	$0x96, c, b, dst; \
	VPTERNLOGQ	$0x96, e, d, dst

// Theta in-place: compute column parities C[0..4] in Z25-Z29, then apply
// D[x] = C[(x+4)%5] ^ ROT(C[(x+1)%5],1) directly into each state lane
// using VPTERNLOGQ to fuse the D formation with the state XOR.
// Z30 holds ROT(C[next],1); VPTERNLOGQ $0x96 three-way XORs
// state ^= C_prev ^ ROT(C_next,1) without an intermediate D register.
// C values in Z25-Z29 are read-only throughout.
#define X8_THETA_INPLACE_AVX512() \
	XOR5_AVX512_8X(Z25, Z0, Z5, Z10, Z15, Z20); \
	XOR5_AVX512_8X(Z26, Z1, Z6, Z11, Z16, Z21); \
	XOR5_AVX512_8X(Z27, Z2, Z7, Z12, Z17, Z22); \
	XOR5_AVX512_8X(Z28, Z3, Z8, Z13, Z18, Z23); \
	XOR5_AVX512_8X(Z29, Z4, Z9, Z14, Z19, Z24); \
	/* D[0] = C[4] ^ ROT(C[1],1) — column 0 */ \
	VPROLQ	$1, Z26, Z30; \
	VPTERNLOGQ	$0x96, Z29, Z30, Z0; \
	VPTERNLOGQ	$0x96, Z29, Z30, Z5; \
	VPTERNLOGQ	$0x96, Z29, Z30, Z10; \
	VPTERNLOGQ	$0x96, Z29, Z30, Z15; \
	VPTERNLOGQ	$0x96, Z29, Z30, Z20; \
	/* D[1] = C[0] ^ ROT(C[2],1) — column 1 */ \
	VPROLQ	$1, Z27, Z30; \
	VPTERNLOGQ	$0x96, Z25, Z30, Z1; \
	VPTERNLOGQ	$0x96, Z25, Z30, Z6; \
	VPTERNLOGQ	$0x96, Z25, Z30, Z11; \
	VPTERNLOGQ	$0x96, Z25, Z30, Z16; \
	VPTERNLOGQ	$0x96, Z25, Z30, Z21; \
	/* D[2] = C[1] ^ ROT(C[3],1) — column 2 */ \
	VPROLQ	$1, Z28, Z30; \
	VPTERNLOGQ	$0x96, Z26, Z30, Z2; \
	VPTERNLOGQ	$0x96, Z26, Z30, Z7; \
	VPTERNLOGQ	$0x96, Z26, Z30, Z12; \
	VPTERNLOGQ	$0x96, Z26, Z30, Z17; \
	VPTERNLOGQ	$0x96, Z26, Z30, Z22; \
	/* D[3] = C[2] ^ ROT(C[4],1) — column 3 */ \
	VPROLQ	$1, Z29, Z30; \
	VPTERNLOGQ	$0x96, Z27, Z30, Z3; \
	VPTERNLOGQ	$0x96, Z27, Z30, Z8; \
	VPTERNLOGQ	$0x96, Z27, Z30, Z13; \
	VPTERNLOGQ	$0x96, Z27, Z30, Z18; \
	VPTERNLOGQ	$0x96, Z27, Z30, Z23; \
	/* D[4] = C[3] ^ ROT(C[0],1) — column 4 */ \
	VPROLQ	$1, Z25, Z30; \
	VPTERNLOGQ	$0x96, Z28, Z30, Z4; \
	VPTERNLOGQ	$0x96, Z28, Z30, Z9; \
	VPTERNLOGQ	$0x96, Z28, Z30, Z14; \
	VPTERNLOGQ	$0x96, Z28, Z30, Z19; \
	VPTERNLOGQ	$0x96, Z28, Z30, Z24

// Rho/Pi/Chi row transform (theta already applied in-place).
#define X8_RPC_MAP_AVX512(L1, L2, L3, L4, L5, R1, R2, R3, R4, R5, A, B, C, D, E) \
	VPROLQ	$R1, L1, Z25; \
	VPROLQ	$R2, L2, Z26; \
	VPROLQ	$R3, L3, Z27; \
	VPROLQ	$R4, L4, Z28; \
	VPROLQ	$R5, L5, Z29; \
	VMOVDQU64	A, Z30; \
	VMOVDQU64	B, Z31; \
	VPTERNLOGQ	$0xD2, C, B, A; \
	VPTERNLOGQ	$0xD2, D, C, B; \
	VPTERNLOGQ	$0xD2, E, D, C; \
	VPTERNLOGQ	$0xD2, Z30, E, D; \
	VPTERNLOGQ	$0xD2, Z31, Z30, E; \
	VMOVDQU64	A, L1; \
	VMOVDQU64	B, L2; \
	VMOVDQU64	C, L3; \
	VMOVDQU64	D, L4; \
	VMOVDQU64	E, L5

// Same as X8_RPC_MAP_AVX512, but xor round constant into lane A after Chi (Iota).
#define X8_RPC_IOTA_MAP_AVX512(L1, L2, L3, L4, L5, R1, R2, R3, R4, R5, A, B, C, D, E, RC_OFF) \
	VPROLQ	$R1, L1, Z25; \
	VPROLQ	$R2, L2, Z26; \
	VPROLQ	$R3, L3, Z27; \
	VPROLQ	$R4, L4, Z28; \
	VPROLQ	$R5, L5, Z29; \
	VMOVDQU64	A, Z30; \
	VMOVDQU64	B, Z31; \
	VPTERNLOGQ	$0xD2, C, B, A; \
	VPTERNLOGQ	$0xD2, D, C, B; \
	VPTERNLOGQ	$0xD2, E, D, C; \
	VPTERNLOGQ	$0xD2, Z30, E, D; \
	VPTERNLOGQ	$0xD2, Z31, Z30, E; \
	VPBROADCASTQ	RC_OFF(R11), Z30; \
	VPXORQ	Z30, A, A; \
	VMOVDQU64	A, L1; \
	VMOVDQU64	B, L2; \
	VMOVDQU64	C, L3; \
	VMOVDQU64	D, L4; \
	VMOVDQU64	E, L5

// Four unrolled rounds in the exact XKCP lane schedule.
#define X8_4ROUNDS_AVX512(off0, off1, off2, off3) \
	X8_THETA_INPLACE_AVX512(); \
	X8_RPC_IOTA_MAP_AVX512(Z0, Z6, Z12, Z18, Z24, 0, 44, 43, 21, 14, Z25, Z26, Z27, Z28, Z29, off0); \
	X8_RPC_MAP_AVX512(Z10, Z16, Z22, Z3, Z9, 3, 45, 61, 28, 20, Z28, Z29, Z25, Z26, Z27); \
	X8_RPC_MAP_AVX512(Z20, Z1, Z7, Z13, Z19, 18, 1, 6, 25, 8, Z26, Z27, Z28, Z29, Z25); \
	X8_RPC_MAP_AVX512(Z5, Z11, Z17, Z23, Z4, 36, 10, 15, 56, 27, Z29, Z25, Z26, Z27, Z28); \
	X8_RPC_MAP_AVX512(Z15, Z21, Z2, Z8, Z14, 41, 2, 62, 55, 39, Z27, Z28, Z29, Z25, Z26); \
	\
	X8_THETA_INPLACE_AVX512(); \
	X8_RPC_IOTA_MAP_AVX512(Z0, Z16, Z7, Z23, Z14, 0, 44, 43, 21, 14, Z25, Z26, Z27, Z28, Z29, off1); \
	X8_RPC_MAP_AVX512(Z20, Z11, Z2, Z18, Z9, 3, 45, 61, 28, 20, Z28, Z29, Z25, Z26, Z27); \
	X8_RPC_MAP_AVX512(Z15, Z6, Z22, Z13, Z4, 18, 1, 6, 25, 8, Z26, Z27, Z28, Z29, Z25); \
	X8_RPC_MAP_AVX512(Z10, Z1, Z17, Z8, Z24, 36, 10, 15, 56, 27, Z29, Z25, Z26, Z27, Z28); \
	X8_RPC_MAP_AVX512(Z5, Z21, Z12, Z3, Z19, 41, 2, 62, 55, 39, Z27, Z28, Z29, Z25, Z26); \
	\
	X8_THETA_INPLACE_AVX512(); \
	X8_RPC_IOTA_MAP_AVX512(Z0, Z11, Z22, Z8, Z19, 0, 44, 43, 21, 14, Z25, Z26, Z27, Z28, Z29, off2); \
	X8_RPC_MAP_AVX512(Z15, Z1, Z12, Z23, Z9, 3, 45, 61, 28, 20, Z28, Z29, Z25, Z26, Z27); \
	X8_RPC_MAP_AVX512(Z5, Z16, Z2, Z13, Z24, 18, 1, 6, 25, 8, Z26, Z27, Z28, Z29, Z25); \
	X8_RPC_MAP_AVX512(Z20, Z6, Z17, Z3, Z14, 36, 10, 15, 56, 27, Z29, Z25, Z26, Z27, Z28); \
	X8_RPC_MAP_AVX512(Z10, Z21, Z7, Z18, Z4, 41, 2, 62, 55, 39, Z27, Z28, Z29, Z25, Z26); \
	\
	X8_THETA_INPLACE_AVX512(); \
	X8_RPC_IOTA_MAP_AVX512(Z0, Z1, Z2, Z3, Z4, 0, 44, 43, 21, 14, Z25, Z26, Z27, Z28, Z29, off3); \
	X8_RPC_MAP_AVX512(Z5, Z6, Z7, Z8, Z9, 3, 45, 61, 28, 20, Z28, Z29, Z25, Z26, Z27); \
	X8_RPC_MAP_AVX512(Z10, Z11, Z12, Z13, Z14, 18, 1, 6, 25, 8, Z26, Z27, Z28, Z29, Z25); \
	X8_RPC_MAP_AVX512(Z15, Z16, Z17, Z18, Z19, 36, 10, 15, 56, 27, Z29, Z25, Z26, Z27, Z28); \
	X8_RPC_MAP_AVX512(Z20, Z21, Z22, Z23, Z24, 41, 2, 62, 55, 39, Z27, Z28, Z29, Z25, Z26)

// ─── AVX-512 x1 Keccak-p[1600,12] permutation macros ───
//
// Based on Andy Polyakov's CRYPTOGAMS keccak1600-avx512.pl (OpenSSL/XKCP).
// Ported to Go Plan 9 assembly.
//
// State layout: one row of the 5×5 state per ZMM register (5 qwords used,
// 3 wasted). Even and odd rounds alternate between two layouts; the
// "harmonize" step converts between them.
//
// Register allocation:
//   Z0-Z4:   State (A00-A40, one row per register)
//   Z5-Z12:  Temporaries
//   Z13-Z16: Theta permutation indices (Theta[1]-Theta[4]; Theta[0]=identity)
//   Z17-Z21: Pi0 permutation indices
//   Z22-Z26: Rhotate0 rotation amounts (even rounds)
//   Z27-Z31: Rhotate1 rotation amounts (odd rounds)
//   K1: 0x01    K2: 0x02    K3: 0x04    K4: 0x08    K5: 0x10    K6: 0x1F
//   R10: round constant pointer
//   AX: round loop counter
//
// Data layout in avx512_x1_consts (1280 bytes, 20 × 64):
//   Offset    Content          Register
//     0       theta_perm[0]    (identity, not loaded)
//    64       theta_perm[1]    Z13
//   128       theta_perm[2]    Z14
//   192       theta_perm[3]    Z15
//   256       theta_perm[4]    Z16
//   320       rhotates1[0]     Z27
//   384       rhotates1[1]     Z28
//   448       rhotates1[2]     Z29
//   512       rhotates1[3]     Z30
//   576       rhotates1[4]     Z31
//   640       rhotates0[0]     Z22
//   704       rhotates0[1]     Z23
//   768       rhotates0[2]     Z24
//   832       rhotates0[3]     Z25
//   896       rhotates0[4]     Z26
//   960       pi0_perm[0]      Z17
//  1024       pi0_perm[1]      Z18
//  1088       pi0_perm[2]      Z19
//  1152       pi0_perm[3]      Z20
//  1216       pi0_perm[4]      Z21

// X1_SETUP_MASKS initializes K1-K6 mask registers.
#define X1_SETUP_MASKS \
	KXNORW K6, K6, K6; \
	KSHIFTRW $15, K6, K1; \
	KSHIFTRW $11, K6, K6; \
	KSHIFTLW $1, K1, K2; \
	KSHIFTLW $2, K1, K3; \
	KSHIFTLW $3, K1, K4; \
	KSHIFTLW $4, K1, K5

// X1_LOAD_CONSTS loads all 19 constant vectors from R8 into Z13-Z31.
// R8 must point to avx512_x1_consts.
#define X1_LOAD_CONSTS \
	VMOVDQU64 64(R8), Z13; \
	VMOVDQU64 128(R8), Z14; \
	VMOVDQU64 192(R8), Z15; \
	VMOVDQU64 256(R8), Z16; \
	VMOVDQU64 320(R8), Z27; \
	VMOVDQU64 384(R8), Z28; \
	VMOVDQU64 448(R8), Z29; \
	VMOVDQU64 512(R8), Z30; \
	VMOVDQU64 576(R8), Z31; \
	VMOVDQU64 640(R8), Z22; \
	VMOVDQU64 704(R8), Z23; \
	VMOVDQU64 768(R8), Z24; \
	VMOVDQU64 832(R8), Z25; \
	VMOVDQU64 896(R8), Z26; \
	VMOVDQU64 960(R8), Z17; \
	VMOVDQU64 1024(R8), Z18; \
	VMOVDQU64 1088(R8), Z19; \
	VMOVDQU64 1152(R8), Z20; \
	VMOVDQU64 1216(R8), Z21

// X1_LOAD_STATE loads State1 from (DI) into Z0-Z4.
// Pre-zeroes registers so masked loads leave elements 5-7 as zero.
#define X1_LOAD_STATE \
	VPXORQ Z0, Z0, Z0; \
	VPXORQ Z1, Z1, Z1; \
	VPXORQ Z2, Z2, Z2; \
	VPXORQ Z3, Z3, Z3; \
	VPXORQ Z4, Z4, Z4; \
	VMOVDQU64 0(DI), K6, Z0; \
	VMOVDQU64 40(DI), K6, Z1; \
	VMOVDQU64 80(DI), K6, Z2; \
	VMOVDQU64 120(DI), K6, Z3; \
	VMOVDQU64 160(DI), K6, Z4

// X1_STORE_STATE stores Z0-Z4 back to State1 at (DI).
#define X1_STORE_STATE \
	VMOVDQU64 Z0, K6, 0(DI); \
	VMOVDQU64 Z1, K6, 40(DI); \
	VMOVDQU64 Z2, K6, 80(DI); \
	VMOVDQU64 Z3, K6, 120(DI); \
	VMOVDQU64 Z4, K6, 160(DI)

// X1_ABSORB_168 XORs 168 bytes (21 lanes) from (SI) into Z0-Z4.
// Uses Z5 as scratch. Advances SI by 168, decrements CX by 168.
#define X1_ABSORB_168 \
	VPXORQ Z5, Z5, Z5; \
	VMOVDQU64 0(SI), K6, Z5; \
	VPXORQ Z5, Z0, Z0; \
	VMOVDQU64 40(SI), K6, Z5; \
	VPXORQ Z5, Z1, Z1; \
	VMOVDQU64 80(SI), K6, Z5; \
	VPXORQ Z5, Z2, Z2; \
	VMOVDQU64 120(SI), K6, Z5; \
	VPXORQ Z5, Z3, Z3; \
	VPXORQ Z5, Z5, Z5; \
	VMOVDQU64 160(SI), K1, Z5; \
	VPXORQ Z5, Z4, Z4; \
	ADDQ $168, SI; \
	SUBQ $168, CX

// X1_EVEN_ROUND performs one even round of Keccak-f[1600].
// R10 points to round constant; advanced by 16 on exit.
#define X1_EVEN_ROUND \
	/* Theta */ \
	VMOVDQA64 Z0, Z5; \
	VPTERNLOGQ $0x96, Z2, Z1, Z0; \
	VPTERNLOGQ $0x96, Z4, Z3, Z0; \
	VPROLQ $1, Z0, Z6; \
	VPERMQ Z0, Z13, Z0; \
	VPERMQ Z6, Z16, Z6; \
	VPTERNLOGQ $0x96, Z0, Z6, Z5; \
	VPTERNLOGQ $0x96, Z0, Z6, Z1; \
	VPTERNLOGQ $0x96, Z0, Z6, Z2; \
	VPTERNLOGQ $0x96, Z0, Z6, Z3; \
	VPTERNLOGQ $0x96, Z0, Z6, Z4; \
	/* Rho */ \
	VPROLVQ Z22, Z5, Z0; \
	VPROLVQ Z23, Z1, Z1; \
	VPROLVQ Z24, Z2, Z2; \
	VPROLVQ Z25, Z3, Z3; \
	VPROLVQ Z26, Z4, Z4; \
	/* Pi */ \
	VPERMQ Z0, Z17, Z0; \
	VPERMQ Z1, Z18, Z1; \
	VPERMQ Z2, Z19, Z2; \
	VPERMQ Z3, Z20, Z3; \
	VPERMQ Z4, Z21, Z4; \
	/* Chi */ \
	VMOVDQA64 Z0, Z5; \
	VMOVDQA64 Z1, Z6; \
	VPTERNLOGQ $0xD2, Z2, Z1, Z0; \
	VPTERNLOGQ $0xD2, Z3, Z2, Z1; \
	VPTERNLOGQ $0xD2, Z4, Z3, Z2; \
	VPTERNLOGQ $0xD2, Z5, Z4, Z3; \
	VPTERNLOGQ $0xD2, Z6, Z5, Z4; \
	/* Iota */ \
	VPXORQ (R10), Z0, K1, Z0; \
	ADDQ $16, R10; \
	/* Harmonize: convert even layout to odd layout */ \
	VPBLENDMQ Z2, Z1, K2, Z6; \
	VPBLENDMQ Z3, Z2, K2, Z7; \
	VPBLENDMQ Z4, Z3, K2, Z8; \
	VPBLENDMQ Z1, Z0, K2, Z5; \
	VPBLENDMQ Z0, Z4, K2, Z9; \
	VPBLENDMQ Z3, Z6, K3, Z6; \
	VPBLENDMQ Z4, Z7, K3, Z7; \
	VPBLENDMQ Z2, Z5, K3, Z5; \
	VPBLENDMQ Z0, Z8, K3, Z8; \
	VPBLENDMQ Z1, Z9, K3, Z9; \
	VPBLENDMQ Z4, Z6, K4, Z6; \
	VPBLENDMQ Z3, Z5, K4, Z5; \
	VPBLENDMQ Z0, Z7, K4, Z7; \
	VPBLENDMQ Z1, Z8, K4, Z8; \
	VPBLENDMQ Z2, Z9, K4, Z9; \
	VPBLENDMQ Z4, Z5, K5, Z5; \
	VPBLENDMQ Z0, Z6, K5, Z6; \
	VPBLENDMQ Z1, Z7, K5, Z7; \
	VPBLENDMQ Z2, Z8, K5, Z8; \
	VPBLENDMQ Z3, Z9, K5, Z9; \
	/* vpermq Z5, identity, Z0 — no-op, handled by odd round */ \
	VPERMQ Z6, Z13, Z1; \
	VPERMQ Z7, Z14, Z2; \
	VPERMQ Z8, Z15, Z3; \
	VPERMQ Z9, Z16, Z4

// X1_ODD_ROUND performs one odd round of Keccak-f[1600].
// R10 must point 8 bytes past the current round constant (reads at -8(R10)).
// Z5 holds the new A00 from the harmonize step (moved to Z0 here).
#define X1_ODD_ROUND \
	/* Theta */ \
	VMOVDQA64 Z5, Z0; \
	VPTERNLOGQ $0x96, Z2, Z1, Z5; \
	VPTERNLOGQ $0x96, Z4, Z3, Z5; \
	VPROLQ $1, Z5, Z6; \
	VPERMQ Z5, Z13, Z5; \
	VPERMQ Z6, Z16, Z6; \
	VPTERNLOGQ $0x96, Z5, Z6, Z0; \
	VPTERNLOGQ $0x96, Z5, Z6, Z3; \
	VPTERNLOGQ $0x96, Z5, Z6, Z1; \
	VPTERNLOGQ $0x96, Z5, Z6, Z4; \
	VPTERNLOGQ $0x96, Z5, Z6, Z2; \
	/* Rho */ \
	VPROLVQ Z27, Z0, Z0; \
	VPROLVQ Z30, Z3, Z6; \
	VPROLVQ Z28, Z1, Z7; \
	VPROLVQ Z31, Z4, Z8; \
	VPROLVQ Z29, Z2, Z9; \
	/* Chi prep: permute A00 for chi's row needs */ \
	VPERMQ Z0, Z16, Z10; \
	VPERMQ Z0, Z15, Z11; \
	/* Iota */ \
	VPXORQ -8(R10), Z0, K1, Z0; \
	/* Pi */ \
	VPERMQ Z6, Z14, Z1; \
	VPERMQ Z7, Z16, Z2; \
	VPERMQ Z8, Z13, Z3; \
	VPERMQ Z9, Z15, Z4; \
	/* Chi (interleaved with permutations for odd layout) */ \
	VPTERNLOGQ $0xD2, Z11, Z10, Z0; \
	VPERMQ Z6, Z13, Z12; \
	VPTERNLOGQ $0xD2, Z6, Z12, Z1; \
	VPERMQ Z7, Z15, Z5; \
	VPERMQ Z7, Z14, Z7; \
	VPTERNLOGQ $0xD2, Z7, Z5, Z2; \
	VPERMQ Z8, Z16, Z6; \
	VPTERNLOGQ $0xD2, Z6, Z8, Z3; \
	VPERMQ Z9, Z14, Z5; \
	VPERMQ Z9, Z13, Z9; \
	VPTERNLOGQ $0xD2, Z9, Z5, Z4
