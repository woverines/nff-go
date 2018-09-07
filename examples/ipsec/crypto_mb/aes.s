#include "textflag.h"

//This is taken directly from golang/src/crypto/aes/asm_amd64.s 
// func expandKeyAsm(nr int, key *byte, enc, dec *uint32) {
// Note that round keys are stored in uint128 format, not uint32
TEXT ·expandKeyAsm(SB), NOSPLIT, $0
	MOVQ   nr+0(FP), CX
	MOVQ   key+8(FP), AX
	MOVQ   enc+16(FP), BX
	MOVQ   dec+24(FP), DX
	MOVUPS (AX), X0

	// enc
	MOVUPS X0, (BX)
	ADDQ   $16, BX
	PXOR   X4, X4      // _expand_key_* expect X4 to be zero
	CMPL   CX, $12
	JE     Lexp_enc196
	JB     Lexp_enc128

Lexp_enc256:
	MOVUPS          16(AX), X2
	MOVUPS          X2, (BX)
	ADDQ            $16, BX
	AESKEYGENASSIST $0x01, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x01, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x02, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x02, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x04, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x04, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x08, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x08, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x10, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x10, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x20, X2, X1
	CALL            _expand_key_256a<>(SB)
	AESKEYGENASSIST $0x20, X0, X1
	CALL            _expand_key_256b<>(SB)
	AESKEYGENASSIST $0x40, X2, X1
	CALL            _expand_key_256a<>(SB)
	JMP             Lexp_dec

Lexp_enc196:
	MOVQ            16(AX), X2
	AESKEYGENASSIST $0x01, X2, X1
	CALL            _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x02, X2, X1
	CALL            _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x04, X2, X1
	CALL            _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x08, X2, X1
	CALL            _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x10, X2, X1
	CALL            _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x20, X2, X1
	CALL            _expand_key_192b<>(SB)
	AESKEYGENASSIST $0x40, X2, X1
	CALL            _expand_key_192a<>(SB)
	AESKEYGENASSIST $0x80, X2, X1
	CALL            _expand_key_192b<>(SB)
	JMP             Lexp_dec

Lexp_enc128:
	AESKEYGENASSIST $0x01, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x02, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x04, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x08, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x10, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x20, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x40, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x80, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x1b, X0, X1
	CALL            _expand_key_128<>(SB)
	AESKEYGENASSIST $0x36, X0, X1
	CALL            _expand_key_128<>(SB)

Lexp_dec:
	// dec
	SUBQ   $16, BX
	MOVUPS (BX), X1
	MOVUPS X1, (DX)
	DECQ   CX

Lexp_dec_loop:
	MOVUPS -16(BX), X1
	AESIMC X1, X0
	MOVUPS X0, 16(DX)
	SUBQ   $16, BX
	ADDQ   $16, DX
	DECQ   CX
	JNZ    Lexp_dec_loop
	MOVUPS -16(BX), X0
	MOVUPS X0, 16(DX)
	RET

TEXT _expand_key_128<>(SB), NOSPLIT, $0
	PSHUFD $0xff, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR   X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR   X4, X0
	PXOR   X1, X0
	MOVUPS X0, (BX)
	ADDQ   $16, BX
	RET

TEXT _expand_key_192a<>(SB), NOSPLIT, $0
	PSHUFD $0x55, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR   X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR   X4, X0
	PXOR   X1, X0

	MOVAPS X2, X5
	MOVAPS X2, X6
	PSLLDQ $0x4, X5
	PSHUFD $0xff, X0, X3
	PXOR   X3, X2
	PXOR   X5, X2

	MOVAPS X0, X1
	SHUFPS $0x44, X0, X6
	MOVUPS X6, (BX)
	SHUFPS $0x4e, X2, X1
	MOVUPS X1, 16(BX)
	ADDQ   $32, BX
	RET

TEXT _expand_key_192b<>(SB), NOSPLIT, $0
	PSHUFD $0x55, X1, X1
	SHUFPS $0x10, X0, X4
	PXOR   X4, X0
	SHUFPS $0x8c, X0, X4
	PXOR   X4, X0
	PXOR   X1, X0

	MOVAPS X2, X5
	PSLLDQ $0x4, X5
	PSHUFD $0xff, X0, X3
	PXOR   X3, X2
	PXOR   X5, X2

	MOVUPS X0, (BX)
	ADDQ   $16, BX
	RET

TEXT _expand_key_256a<>(SB), NOSPLIT, $0
	JMP _expand_key_128<>(SB)

TEXT _expand_key_256b<>(SB), NOSPLIT, $0
	PSHUFD $0xaa, X1, X1
	SHUFPS $0x10, X2, X4
	PXOR   X4, X2
	SHUFPS $0x8c, X2, X4
	PXOR   X4, X2
	PXOR   X1, X2

	MOVUPS X2, (BX)
	ADDQ   $16, BX
	RET


// This is asm block routine unrolled x8 and acting on 8 input blocks

// func encrypt8BlocksAsm(xk *uint32, dst, src [][]byte)
TEXT ·encrypt8BlocksAsm(SB), NOSPLIT, $0
	// For now 128 only
	MOVQ       xk+0(FP), AX
	MOVQ       dst+8(FP), DI  // dst
	MOVQ       src+32(FP), SI // src
	MOVQ       (SI), BX // &src[0]
	MOVQ       24(SI), BP // &src[1] ...
	MOVQ       48(SI), R9
	MOVQ       72(SI), R10
	MOVQ       96(SI), R11
	MOVQ       120(SI), R12
	MOVQ       144(SI), R13
	MOVQ       168(SI), R14
	MOVUPS     0(AX), X0 // Key
	MOVUPS     0(BX), X1 //src[0]
	MOVUPS     0(BP), X2
	MOVUPS     0(R9), X3
	MOVUPS     0(R10), X4
	MOVUPS     0(R11), X5
	MOVUPS     0(R12), X6
	MOVUPS     0(R13), X7
	MOVUPS     0(R14), X8
	ADDQ       $16, AX
	PXOR       X0, X1
	PXOR       X0, X2
	PXOR       X0, X3
	PXOR       X0, X4
	PXOR       X0, X5
	PXOR       X0, X6
	PXOR       X0, X7
	PXOR       X0, X8
	MOVUPS     0(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     16(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     32(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     48(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     64(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     80(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     96(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     112(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     128(AX), X0
	AESENC     X0, X1
	AESENC     X0, X2
	AESENC     X0, X3
	AESENC     X0, X4
	AESENC     X0, X5
	AESENC     X0, X6
	AESENC     X0, X7
	AESENC     X0, X8
	MOVUPS     144(AX), X0
	AESENCLAST X0, X1
	AESENCLAST X0, X2
	AESENCLAST X0, X3
	AESENCLAST X0, X4
	AESENCLAST X0, X5
	AESENCLAST X0, X6
	AESENCLAST X0, X7
	AESENCLAST X0, X8
	MOVQ       (DI), DX // &dst[0]
	MOVQ       24(DI), SI
	MOVQ       48(DI), AX
	MOVQ       72(DI), BX
	MOVQ       96(DI), CX
	MOVQ       120(DI), BP
	MOVQ       144(DI), R8
	MOVQ       168(DI), R9
	MOVUPS     X1, 0(DX)
	MOVUPS     X2, 0(SI)
	MOVUPS     X3, 0(AX)
	MOVUPS     X4, 0(BX)
	MOVUPS     X5, 0(CX)
	MOVUPS     X6, 0(BP)
	MOVUPS     X7, 0(R8)
	MOVUPS     X8, 0(R9)
	RET
