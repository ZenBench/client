
// extern int mdfourmmx(unsigned char *out, unsigned char *in, int n) __attribute__((regparm(3)));

#ifdef UNDERSCORES
#define mdfourmmx	_mdfourmmx
#endif

.globl mdfourmmx

.data
.align(16)
const_init_a:
.long 0x67452301
.long 0x67452301
const_init_b:
.long 0xefcdab89
.long 0xefcdab89
const_init_c:
.long 0x98badcfe
.long 0x98badcfe
const_init_d:
.long 0x10325476
.long 0x10325476

const_stage2:
.long 0x5a827999
.long 0x5a827999
const_stage3:
.long 0x6ed9eba1
.long 0x6ed9eba1

.align(16)
buffer:
.zero(64*2)

#define ctxa %mm0
#define ctxb %mm1
#define ctxc %mm2
#define ctxd %mm3
#define tmp1 %mm4
#define tmp2 %mm5
#define tmp3 %mm6
#define tmp4 %mm7


//#define F_MMX(x, y, z)			(z ^ (x & (y ^ z)))

#define F(x,y,z) \
	movq y, tmp1; \
	pxor z, tmp1; \
	pand x, tmp1; \
	pxor z, tmp1

//#define G_MMX(x, y, z)			((x & (y | z)) | (y & z))

#define G(x,y,z) \
	movq y, tmp1; \
	movq y, tmp2; \
	por z, tmp1; \
	pand z, tmp2; \
	pand x, tmp1; \
	por tmp2, tmp1

//#define H_MMX(x, y, z)			(x ^ y ^ z)
#define H(x,y,z) \
	movq x, tmp1; \
	pxor y, tmp1; \
	pxor z, tmp1

//#define STEP_MMX(f, a, b, c, d, x, s) \
//	(a) += f((b), (c), (d)) + (x); \
//	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

#define STEP1(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*8)(%edx), tmp1; \
	paddd tmp1, a; \
	movq a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a

#define STEP2(f, a, b, c, d, x, s) \
	f(b, c, d); \
	paddd (x*8)(%edx), tmp1; \
	paddd tmp4, tmp1; \
	paddd tmp1, a; \
	movq a, tmp3; \
	pslld $s, a; \
	psrld $(32-s), tmp3; \
	por tmp3, a


.text
/*
 * Try to do some asm md4 w/ mmx
 * %eax ptr -> out
 * %edx ptr -> in
 * %ecx n
 */

mdfourmmx:
	 //MD4 Init
	 pusha
	
	shl $3, %ecx
	mov %ecx, %ebx
	and $0xffff, %ecx
	shrl $16,  %ebx
	// %ecx contient la taille du premier mdp
	// %edx celle du second
	mov %ecx, (14*8)(%edx)
	mov %ebx, (14*8+4)(%edx)

	movq const_init_a, ctxa
	movq const_init_b, ctxb
	movq const_init_c, ctxc
	movq const_init_d, ctxd

	STEP1(F, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 1, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 2, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 3, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 4, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 5, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 7, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 8, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 9, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 10, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 11, 19)
	STEP1(F, ctxa, ctxb, ctxc, ctxd, 12, 3)
	STEP1(F, ctxd, ctxa, ctxb, ctxc, 13, 7)
	STEP1(F, ctxc, ctxd, ctxa, ctxb, 14, 11)
	STEP1(F, ctxb, ctxc, ctxd, ctxa, 15, 19)

	movq const_stage2, tmp4

	STEP2(G, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 4, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 8, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 12, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 5, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 9, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 13, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 6, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 10, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 14, 13)
	STEP2(G, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(G, ctxd, ctxa, ctxb, ctxc, 7, 5)
	STEP2(G, ctxc, ctxd, ctxa, ctxb, 11, 9)
	STEP2(G, ctxb, ctxc, ctxd, ctxa, 15, 13)

	movq const_stage3, tmp4

	STEP2(H, ctxa, ctxb, ctxc, ctxd, 0, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 8, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 4, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 12, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 2, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 10, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 6, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 14, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 1, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 9, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 5, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 13, 15)
	STEP2(H, ctxa, ctxb, ctxc, ctxd, 3, 3)
	STEP2(H, ctxd, ctxa, ctxb, ctxc, 11, 9)
	STEP2(H, ctxc, ctxd, ctxa, ctxb, 7, 11)
	STEP2(H, ctxb, ctxc, ctxd, ctxa, 15, 15)

	paddd const_init_a, ctxa
	paddd const_init_b, ctxb
	paddd const_init_c, ctxc
	paddd const_init_d, ctxd


	movq ctxa, 0(%eax)
	movq ctxb, 8(%eax)
	movq ctxc, 16(%eax)
	movq ctxd, 24(%eax)

	popa
	movd ctxa, %eax
	emms
	
	ret

#ifdef __ELF__
.section .note.GNU-stack,"",@progbits
#endif
