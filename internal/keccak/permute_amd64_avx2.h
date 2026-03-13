// Keccak-f[1600]×4 AVX2 macros shared between permute_amd64.s and helpers_amd64.s.
//
// Register conventions:
//   R8   = source buffer pointer (read)
//   R9   = destination buffer pointer (write)
//   Y0-Y4  = current plane inputs
//   Y5-Y9  = theta D values
//   Y10-Y12 = chi scratch
//   Y13    = rotation scratch
//   Y15    = round constant (CHI_IOTA only)

// ROT64_AVX2_4X rotates each of the 4 packed uint64s in reg left by amount bits.
// Clobbers Y13.
#define ROT64_AVX2_4X(reg, amount) \
	VMOVDQU	reg, Y13; \
	VPSLLQ	$amount, reg, reg; \
	VPSRLQ	$(64-amount), Y13, Y13; \
	VPOR	Y13, reg, reg

// CHI_AVX2_4X computes the chi step for one plane and writes 5 lanes to R9.
// Inputs: Y0-Y4 (plane after rho+pi), base = starting lane index in R9 buffer.
// Clobbers Y10, Y11, Y12.
#define CHI_AVX2_4X(base) \
	VMOVDQU	Y0, Y10; \
	VMOVDQU	Y1, Y11; \
	VMOVDQU	Y1, Y12; \
	VPANDN	Y2, Y12, Y12; \
	VPXOR	Y0, Y12, Y12; \
	VMOVDQU	Y12, (base+0)*32(R9); \
	VMOVDQU	Y2, Y12; \
	VPANDN	Y3, Y12, Y12; \
	VPXOR	Y1, Y12, Y12; \
	VMOVDQU	Y12, (base+1)*32(R9); \
	VMOVDQU	Y3, Y12; \
	VPANDN	Y4, Y12, Y12; \
	VPXOR	Y2, Y12, Y12; \
	VMOVDQU	Y12, (base+2)*32(R9); \
	VMOVDQU	Y4, Y12; \
	VPANDN	Y10, Y12, Y12; \
	VPXOR	Y3, Y12, Y12; \
	VMOVDQU	Y12, (base+3)*32(R9); \
	VPANDN	Y11, Y10, Y10; \
	VPXOR	Y4, Y10, Y10; \
	VMOVDQU	Y10, (base+4)*32(R9)

// X4_KECCAK_ROUND performs one complete round of the x4 AVX2 Keccak permutation.
// Reads state from R8, writes to R9, loads round constant from (R11) into Y15.
// Clobbers Y0-Y15.
#define X4_KECCAK_ROUND \
	/* === THETA === */ \
	/* Column parities */ \
	VMOVDQU	0*32(R8), Y0; \
	VMOVDQU	5*32(R8), Y14; \
	VPXOR	Y14, Y0, Y0; \
	VMOVDQU	10*32(R8), Y14; \
	VPXOR	Y14, Y0, Y0; \
	VMOVDQU	15*32(R8), Y14; \
	VPXOR	Y14, Y0, Y0; \
	VMOVDQU	20*32(R8), Y14; \
	VPXOR	Y14, Y0, Y0; \
	\
	VMOVDQU	1*32(R8), Y1; \
	VMOVDQU	6*32(R8), Y14; \
	VPXOR	Y14, Y1, Y1; \
	VMOVDQU	11*32(R8), Y14; \
	VPXOR	Y14, Y1, Y1; \
	VMOVDQU	16*32(R8), Y14; \
	VPXOR	Y14, Y1, Y1; \
	VMOVDQU	21*32(R8), Y14; \
	VPXOR	Y14, Y1, Y1; \
	\
	VMOVDQU	2*32(R8), Y2; \
	VMOVDQU	7*32(R8), Y14; \
	VPXOR	Y14, Y2, Y2; \
	VMOVDQU	12*32(R8), Y14; \
	VPXOR	Y14, Y2, Y2; \
	VMOVDQU	17*32(R8), Y14; \
	VPXOR	Y14, Y2, Y2; \
	VMOVDQU	22*32(R8), Y14; \
	VPXOR	Y14, Y2, Y2; \
	\
	VMOVDQU	3*32(R8), Y3; \
	VMOVDQU	8*32(R8), Y14; \
	VPXOR	Y14, Y3, Y3; \
	VMOVDQU	13*32(R8), Y14; \
	VPXOR	Y14, Y3, Y3; \
	VMOVDQU	18*32(R8), Y14; \
	VPXOR	Y14, Y3, Y3; \
	VMOVDQU	23*32(R8), Y14; \
	VPXOR	Y14, Y3, Y3; \
	\
	VMOVDQU	4*32(R8), Y4; \
	VMOVDQU	9*32(R8), Y14; \
	VPXOR	Y14, Y4, Y4; \
	VMOVDQU	14*32(R8), Y14; \
	VPXOR	Y14, Y4, Y4; \
	VMOVDQU	19*32(R8), Y14; \
	VPXOR	Y14, Y4, Y4; \
	VMOVDQU	24*32(R8), Y14; \
	VPXOR	Y14, Y4, Y4; \
	\
	/* Diffusion */ \
	VMOVDQU	Y1, Y5; \
	ROT64_AVX2_4X(Y5, 1); \
	VPXOR	Y4, Y5, Y5; \
	\
	VMOVDQU	Y2, Y6; \
	ROT64_AVX2_4X(Y6, 1); \
	VPXOR	Y0, Y6, Y6; \
	\
	VMOVDQU	Y3, Y7; \
	ROT64_AVX2_4X(Y7, 1); \
	VPXOR	Y1, Y7, Y7; \
	\
	VMOVDQU	Y4, Y8; \
	ROT64_AVX2_4X(Y8, 1); \
	VPXOR	Y2, Y8, Y8; \
	\
	VMOVDQU	Y0, Y9; \
	ROT64_AVX2_4X(Y9, 1); \
	VPXOR	Y3, Y9, Y9; \
	\
	/* === RHO + PI + CHI + IOTA === */ \
	/* Row 0 */ \
	VMOVDQU	0*32(R8), Y0; \
	VPXOR	Y5, Y0, Y0; \
	\
	VMOVDQU	6*32(R8), Y1; \
	VPXOR	Y6, Y1, Y1; \
	ROT64_AVX2_4X(Y1, 44); \
	\
	VMOVDQU	12*32(R8), Y2; \
	VPXOR	Y7, Y2, Y2; \
	ROT64_AVX2_4X(Y2, 43); \
	\
	VMOVDQU	18*32(R8), Y3; \
	VPXOR	Y8, Y3, Y3; \
	ROT64_AVX2_4X(Y3, 21); \
	\
	VMOVDQU	24*32(R8), Y4; \
	VPXOR	Y9, Y4, Y4; \
	ROT64_AVX2_4X(Y4, 14); \
	\
	VMOVDQU	(R11), Y15; \
	CHI_IOTA_AVX2_4X(0); \
	\
	/* Row 1 */ \
	VMOVDQU	3*32(R8), Y0; \
	VPXOR	Y8, Y0, Y0; \
	ROT64_AVX2_4X(Y0, 28); \
	\
	VMOVDQU	9*32(R8), Y1; \
	VPXOR	Y9, Y1, Y1; \
	ROT64_AVX2_4X(Y1, 20); \
	\
	VMOVDQU	10*32(R8), Y2; \
	VPXOR	Y5, Y2, Y2; \
	ROT64_AVX2_4X(Y2, 3); \
	\
	VMOVDQU	16*32(R8), Y3; \
	VPXOR	Y6, Y3, Y3; \
	ROT64_AVX2_4X(Y3, 45); \
	\
	VMOVDQU	22*32(R8), Y4; \
	VPXOR	Y7, Y4, Y4; \
	ROT64_AVX2_4X(Y4, 61); \
	\
	CHI_AVX2_4X(5); \
	\
	/* Row 2 */ \
	VMOVDQU	1*32(R8), Y0; \
	VPXOR	Y6, Y0, Y0; \
	ROT64_AVX2_4X(Y0, 1); \
	\
	VMOVDQU	7*32(R8), Y1; \
	VPXOR	Y7, Y1, Y1; \
	ROT64_AVX2_4X(Y1, 6); \
	\
	VMOVDQU	13*32(R8), Y2; \
	VPXOR	Y8, Y2, Y2; \
	ROT64_AVX2_4X(Y2, 25); \
	\
	VMOVDQU	19*32(R8), Y3; \
	VPXOR	Y9, Y3, Y3; \
	ROT64_AVX2_4X(Y3, 8); \
	\
	VMOVDQU	20*32(R8), Y4; \
	VPXOR	Y5, Y4, Y4; \
	ROT64_AVX2_4X(Y4, 18); \
	\
	CHI_AVX2_4X(10); \
	\
	/* Row 3 */ \
	VMOVDQU	4*32(R8), Y0; \
	VPXOR	Y9, Y0, Y0; \
	ROT64_AVX2_4X(Y0, 27); \
	\
	VMOVDQU	5*32(R8), Y1; \
	VPXOR	Y5, Y1, Y1; \
	ROT64_AVX2_4X(Y1, 36); \
	\
	VMOVDQU	11*32(R8), Y2; \
	VPXOR	Y6, Y2, Y2; \
	ROT64_AVX2_4X(Y2, 10); \
	\
	VMOVDQU	17*32(R8), Y3; \
	VPXOR	Y7, Y3, Y3; \
	ROT64_AVX2_4X(Y3, 15); \
	\
	VMOVDQU	23*32(R8), Y4; \
	VPXOR	Y8, Y4, Y4; \
	ROT64_AVX2_4X(Y4, 56); \
	\
	CHI_AVX2_4X(15); \
	\
	/* Row 4 */ \
	VMOVDQU	2*32(R8), Y0; \
	VPXOR	Y7, Y0, Y0; \
	ROT64_AVX2_4X(Y0, 62); \
	\
	VMOVDQU	8*32(R8), Y1; \
	VPXOR	Y8, Y1, Y1; \
	ROT64_AVX2_4X(Y1, 55); \
	\
	VMOVDQU	14*32(R8), Y2; \
	VPXOR	Y9, Y2, Y2; \
	ROT64_AVX2_4X(Y2, 39); \
	\
	VMOVDQU	15*32(R8), Y3; \
	VPXOR	Y5, Y3, Y3; \
	ROT64_AVX2_4X(Y3, 41); \
	\
	VMOVDQU	21*32(R8), Y4; \
	VPXOR	Y6, Y4, Y4; \
	ROT64_AVX2_4X(Y4, 2); \
	\
	CHI_AVX2_4X(20)

// CHI_IOTA_AVX2_4X computes chi + iota for the first plane.
// Same as CHI_AVX2_4X but XORs the round constant from Y15 into lane 0.
#define CHI_IOTA_AVX2_4X(base) \
	VMOVDQU	Y0, Y10; \
	VMOVDQU	Y1, Y11; \
	VMOVDQU	Y1, Y12; \
	VPANDN	Y2, Y12, Y12; \
	VPXOR	Y0, Y12, Y12; \
	VPXOR	Y15, Y12, Y12; \
	VMOVDQU	Y12, (base+0)*32(R9); \
	VMOVDQU	Y2, Y12; \
	VPANDN	Y3, Y12, Y12; \
	VPXOR	Y1, Y12, Y12; \
	VMOVDQU	Y12, (base+1)*32(R9); \
	VMOVDQU	Y3, Y12; \
	VPANDN	Y4, Y12, Y12; \
	VPXOR	Y2, Y12, Y12; \
	VMOVDQU	Y12, (base+2)*32(R9); \
	VMOVDQU	Y4, Y12; \
	VPANDN	Y10, Y12, Y12; \
	VPXOR	Y3, Y12, Y12; \
	VMOVDQU	Y12, (base+3)*32(R9); \
	VPANDN	Y11, Y10, Y10; \
	VPXOR	Y4, Y10, Y10; \
	VMOVDQU	Y10, (base+4)*32(R9)
