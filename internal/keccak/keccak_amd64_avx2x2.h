// Keccak-f[1600]×2 AVX2 (VEX-128) macros shared between permute_amd64.s and helpers_amd64.s.
//
// Register conventions:
//   R8   = source buffer pointer (read)
//   R9   = destination buffer pointer (write)
//   R11  = round constant pointer
//   X0-X4  = current plane inputs
//   X5-X9  = theta D values
//   X10-X12 = chi scratch
//   X13    = rotation scratch
//   X14    = theta column parity scratch
//   X15    = round constant (CHI_IOTA only)

// ROT64_AVX2_2X rotates each of the 2 packed uint64s in reg left by amount bits.
// Clobbers X13.
#define ROT64_AVX2_2X(reg, amount) \
	VPSLLQ	$amount, reg, X13; \
	VPSRLQ	$(64-amount), reg, reg; \
	VPOR	X13, reg, reg

// CHI_AVX2_2X computes the chi step for one plane and writes 5 lanes to R9.
// Inputs: X0-X4 (plane after rho+pi), base = starting lane index in R9 buffer.
// Clobbers X10, X11, X12.
#define CHI_AVX2_2X(base) \
	VMOVDQU	X0, X10; \
	VMOVDQU	X1, X11; \
	VPANDN	X2, X1, X12; \
	VPXOR	X0, X12, X12; \
	VMOVDQU	X12, (base+0)*16(R9); \
	VPANDN	X3, X2, X12; \
	VPXOR	X1, X12, X12; \
	VMOVDQU	X12, (base+1)*16(R9); \
	VPANDN	X4, X3, X12; \
	VPXOR	X2, X12, X12; \
	VMOVDQU	X12, (base+2)*16(R9); \
	VPANDN	X10, X4, X12; \
	VPXOR	X3, X12, X12; \
	VMOVDQU	X12, (base+3)*16(R9); \
	VPANDN	X11, X10, X10; \
	VPXOR	X4, X10, X10; \
	VMOVDQU	X10, (base+4)*16(R9)

// CHI_IOTA_AVX2_2X computes chi + iota for the first plane.
// Same as CHI_AVX2_2X but XORs the round constant from X15 into lane 0.
#define CHI_IOTA_AVX2_2X(base) \
	VMOVDQU	X0, X10; \
	VMOVDQU	X1, X11; \
	VPANDN	X2, X1, X12; \
	VPXOR	X0, X12, X12; \
	VPXOR	X15, X12, X12; \
	VMOVDQU	X12, (base+0)*16(R9); \
	VPANDN	X3, X2, X12; \
	VPXOR	X1, X12, X12; \
	VMOVDQU	X12, (base+1)*16(R9); \
	VPANDN	X4, X3, X12; \
	VPXOR	X2, X12, X12; \
	VMOVDQU	X12, (base+2)*16(R9); \
	VPANDN	X10, X4, X12; \
	VPXOR	X3, X12, X12; \
	VMOVDQU	X12, (base+3)*16(R9); \
	VPANDN	X11, X10, X10; \
	VPXOR	X4, X10, X10; \
	VMOVDQU	X10, (base+4)*16(R9)

// X2_KECCAK_ROUND performs one complete round of the x2 AVX2 Keccak permutation.
// Reads state from R8, writes to R9, loads round constant from (R11) into X15.
// Clobbers X0-X15.
#define X2_KECCAK_ROUND \
	/* === THETA === */ \
	/* Column parities */ \
	VMOVDQU	0*16(R8), X0; \
	VMOVDQU	5*16(R8), X14; \
	VPXOR	X14, X0, X0; \
	VMOVDQU	10*16(R8), X14; \
	VPXOR	X14, X0, X0; \
	VMOVDQU	15*16(R8), X14; \
	VPXOR	X14, X0, X0; \
	VMOVDQU	20*16(R8), X14; \
	VPXOR	X14, X0, X0; \
	\
	VMOVDQU	1*16(R8), X1; \
	VMOVDQU	6*16(R8), X14; \
	VPXOR	X14, X1, X1; \
	VMOVDQU	11*16(R8), X14; \
	VPXOR	X14, X1, X1; \
	VMOVDQU	16*16(R8), X14; \
	VPXOR	X14, X1, X1; \
	VMOVDQU	21*16(R8), X14; \
	VPXOR	X14, X1, X1; \
	\
	VMOVDQU	2*16(R8), X2; \
	VMOVDQU	7*16(R8), X14; \
	VPXOR	X14, X2, X2; \
	VMOVDQU	12*16(R8), X14; \
	VPXOR	X14, X2, X2; \
	VMOVDQU	17*16(R8), X14; \
	VPXOR	X14, X2, X2; \
	VMOVDQU	22*16(R8), X14; \
	VPXOR	X14, X2, X2; \
	\
	VMOVDQU	3*16(R8), X3; \
	VMOVDQU	8*16(R8), X14; \
	VPXOR	X14, X3, X3; \
	VMOVDQU	13*16(R8), X14; \
	VPXOR	X14, X3, X3; \
	VMOVDQU	18*16(R8), X14; \
	VPXOR	X14, X3, X3; \
	VMOVDQU	23*16(R8), X14; \
	VPXOR	X14, X3, X3; \
	\
	VMOVDQU	4*16(R8), X4; \
	VMOVDQU	9*16(R8), X14; \
	VPXOR	X14, X4, X4; \
	VMOVDQU	14*16(R8), X14; \
	VPXOR	X14, X4, X4; \
	VMOVDQU	19*16(R8), X14; \
	VPXOR	X14, X4, X4; \
	VMOVDQU	24*16(R8), X14; \
	VPXOR	X14, X4, X4; \
	\
	/* Diffusion: D[x] = C[(x-1)%5] ^ ROL64(C[(x+1)%5], 1) */ \
	VPSLLQ	$1, X1, X5; \
	VPSRLQ	$63, X1, X13; \
	VPOR	X13, X5, X5; \
	VPXOR	X4, X5, X5; \
	\
	VPSLLQ	$1, X2, X6; \
	VPSRLQ	$63, X2, X13; \
	VPOR	X13, X6, X6; \
	VPXOR	X0, X6, X6; \
	\
	VPSLLQ	$1, X3, X7; \
	VPSRLQ	$63, X3, X13; \
	VPOR	X13, X7, X7; \
	VPXOR	X1, X7, X7; \
	\
	VPSLLQ	$1, X4, X8; \
	VPSRLQ	$63, X4, X13; \
	VPOR	X13, X8, X8; \
	VPXOR	X2, X8, X8; \
	\
	VPSLLQ	$1, X0, X9; \
	VPSRLQ	$63, X0, X13; \
	VPOR	X13, X9, X9; \
	VPXOR	X3, X9, X9; \
	\
	/* === RHO + PI + CHI + IOTA === */ \
	/* Row 0 */ \
	VMOVDQU	0*16(R8), X0; \
	VPXOR	X5, X0, X0; \
	\
	VMOVDQU	6*16(R8), X1; \
	VPXOR	X6, X1, X1; \
	ROT64_AVX2_2X(X1, 44); \
	\
	VMOVDQU	12*16(R8), X2; \
	VPXOR	X7, X2, X2; \
	ROT64_AVX2_2X(X2, 43); \
	\
	VMOVDQU	18*16(R8), X3; \
	VPXOR	X8, X3, X3; \
	ROT64_AVX2_2X(X3, 21); \
	\
	VMOVDQU	24*16(R8), X4; \
	VPXOR	X9, X4, X4; \
	ROT64_AVX2_2X(X4, 14); \
	\
	VMOVDQU	(R11), X15; \
	CHI_IOTA_AVX2_2X(0); \
	\
	/* Row 1 */ \
	VMOVDQU	3*16(R8), X0; \
	VPXOR	X8, X0, X0; \
	ROT64_AVX2_2X(X0, 28); \
	\
	VMOVDQU	9*16(R8), X1; \
	VPXOR	X9, X1, X1; \
	ROT64_AVX2_2X(X1, 20); \
	\
	VMOVDQU	10*16(R8), X2; \
	VPXOR	X5, X2, X2; \
	ROT64_AVX2_2X(X2, 3); \
	\
	VMOVDQU	16*16(R8), X3; \
	VPXOR	X6, X3, X3; \
	ROT64_AVX2_2X(X3, 45); \
	\
	VMOVDQU	22*16(R8), X4; \
	VPXOR	X7, X4, X4; \
	ROT64_AVX2_2X(X4, 61); \
	\
	CHI_AVX2_2X(5); \
	\
	/* Row 2 */ \
	VMOVDQU	1*16(R8), X0; \
	VPXOR	X6, X0, X0; \
	ROT64_AVX2_2X(X0, 1); \
	\
	VMOVDQU	7*16(R8), X1; \
	VPXOR	X7, X1, X1; \
	ROT64_AVX2_2X(X1, 6); \
	\
	VMOVDQU	13*16(R8), X2; \
	VPXOR	X8, X2, X2; \
	ROT64_AVX2_2X(X2, 25); \
	\
	VMOVDQU	19*16(R8), X3; \
	VPXOR	X9, X3, X3; \
	ROT64_AVX2_2X(X3, 8); \
	\
	VMOVDQU	20*16(R8), X4; \
	VPXOR	X5, X4, X4; \
	ROT64_AVX2_2X(X4, 18); \
	\
	CHI_AVX2_2X(10); \
	\
	/* Row 3 */ \
	VMOVDQU	4*16(R8), X0; \
	VPXOR	X9, X0, X0; \
	ROT64_AVX2_2X(X0, 27); \
	\
	VMOVDQU	5*16(R8), X1; \
	VPXOR	X5, X1, X1; \
	ROT64_AVX2_2X(X1, 36); \
	\
	VMOVDQU	11*16(R8), X2; \
	VPXOR	X6, X2, X2; \
	ROT64_AVX2_2X(X2, 10); \
	\
	VMOVDQU	17*16(R8), X3; \
	VPXOR	X7, X3, X3; \
	ROT64_AVX2_2X(X3, 15); \
	\
	VMOVDQU	23*16(R8), X4; \
	VPXOR	X8, X4, X4; \
	ROT64_AVX2_2X(X4, 56); \
	\
	CHI_AVX2_2X(15); \
	\
	/* Row 4 */ \
	VMOVDQU	2*16(R8), X0; \
	VPXOR	X7, X0, X0; \
	ROT64_AVX2_2X(X0, 62); \
	\
	VMOVDQU	8*16(R8), X1; \
	VPXOR	X8, X1, X1; \
	ROT64_AVX2_2X(X1, 55); \
	\
	VMOVDQU	14*16(R8), X2; \
	VPXOR	X9, X2, X2; \
	ROT64_AVX2_2X(X2, 39); \
	\
	VMOVDQU	15*16(R8), X3; \
	VPXOR	X5, X3, X3; \
	ROT64_AVX2_2X(X3, 41); \
	\
	VMOVDQU	21*16(R8), X4; \
	VPXOR	X6, X4, X4; \
	ROT64_AVX2_2X(X4, 2); \
	\
	CHI_AVX2_2X(20)
