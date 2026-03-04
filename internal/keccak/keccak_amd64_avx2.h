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
