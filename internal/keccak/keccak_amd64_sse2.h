// Keccak-f[1600]×2 SSE2 macros shared between permute_amd64.s and helpers_amd64.s.
//
// Register conventions:
//   R8   = source buffer pointer (read)
//   R9   = destination buffer pointer (write)
//   X0-X4  = current plane inputs
//   X5-X9  = theta D values
//   X10-X12 = chi scratch
//   X13    = rotation scratch
//   X15    = round constant (CHI_IOTA only)

// ROT64_SSE2 rotates each of the 2 packed uint64s in reg left by amount bits.
// Clobbers X13.
#define ROT64_SSE2(reg, amount) \
	MOVOU	reg, X13; \
	PSLLQ	$amount, reg; \
	PSRLQ	$(64-amount), X13; \
	POR	X13, reg

// CHI_SSE2 computes the chi step for one plane and writes 5 lanes to R9.
// Inputs: X0-X4 (plane after rho+pi), base = starting lane index in R9 buffer.
// Clobbers X10, X11, X12.
#define CHI_SSE2(base) \
	MOVOU	X0, X10; \
	MOVOU	X1, X11; \
	/* out[0] = bc0 ^ (~bc1 & bc2) */ \
	MOVOU	X1, X12; \
	PANDN	X2, X12; \
	PXOR	X0, X12; \
	MOVOU	X12, (base+0)*16(R9); \
	/* out[1] = bc1 ^ (~bc2 & bc3) */ \
	MOVOU	X2, X12; \
	PANDN	X3, X12; \
	PXOR	X1, X12; \
	MOVOU	X12, (base+1)*16(R9); \
	/* out[2] = bc2 ^ (~bc3 & bc4) */ \
	MOVOU	X3, X12; \
	PANDN	X4, X12; \
	PXOR	X2, X12; \
	MOVOU	X12, (base+2)*16(R9); \
	/* out[3] = bc3 ^ (~bc4 & bc0_saved) */ \
	MOVOU	X4, X12; \
	PANDN	X10, X12; \
	PXOR	X3, X12; \
	MOVOU	X12, (base+3)*16(R9); \
	/* out[4] = bc4 ^ (~bc0_saved & bc1_saved) */ \
	PANDN	X11, X10; \
	PXOR	X4, X10; \
	MOVOU	X10, (base+4)*16(R9)

// CHI_IOTA_SSE2 computes chi + iota for the first plane.
// Same as CHI_SSE2 but XORs the round constant from X15 into lane 0.
#define CHI_IOTA_SSE2(base) \
	MOVOU	X0, X10; \
	MOVOU	X1, X11; \
	MOVOU	X1, X12; \
	PANDN	X2, X12; \
	PXOR	X0, X12; \
	PXOR	X15, X12; \
	MOVOU	X12, (base+0)*16(R9); \
	MOVOU	X2, X12; \
	PANDN	X3, X12; \
	PXOR	X1, X12; \
	MOVOU	X12, (base+1)*16(R9); \
	MOVOU	X3, X12; \
	PANDN	X4, X12; \
	PXOR	X2, X12; \
	MOVOU	X12, (base+2)*16(R9); \
	MOVOU	X4, X12; \
	PANDN	X10, X12; \
	PXOR	X3, X12; \
	MOVOU	X12, (base+3)*16(R9); \
	PANDN	X11, X10; \
	PXOR	X4, X10; \
	MOVOU	X10, (base+4)*16(R9)
