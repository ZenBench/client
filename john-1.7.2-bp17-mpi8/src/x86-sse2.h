/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-2002 by Solar Designer
 */

/*
 * Architecture specific parameters for x86 with MMX.
 */

#ifndef _JOHN_ARCH_H
#define _JOHN_ARCH_H

#define ARCH_WORD			long
#define ARCH_SIZE			4
#define ARCH_BITS			32
#define ARCH_BITS_LOG			5
#define ARCH_BITS_STR			"32"
#define ARCH_LITTLE_ENDIAN		1
#define ARCH_INT_GT_32			0
#define ARCH_ALLOWS_UNALIGNED		1
#define ARCH_INDEX(x)			((unsigned int)(unsigned char)(x))

#if defined(__CYGWIN32__) || defined(__BEOS__)
#define OS_TIMER			0
#else
#define OS_TIMER			1
#endif
#define OS_FLOCK			1

#define CPU_DETECT			1
#define CPU_REQ				1
#define CPU_NAME			"MMX"
#ifndef CPU_FALLBACK
#define CPU_FALLBACK			0
#endif
#if CPU_FALLBACK
#define CPU_FALLBACK_BINARY		"john-non-mmx"
#endif

#define DES_ASM				1
#define DES_128K			0
#define DES_X2				1
#define DES_MASK			1
#define DES_SCALE			0
#define DES_EXTB			0
#define DES_COPY			1
#define DES_STD_ALGORITHM_NAME		"48/64 4K MMX"
#define DES_BS_ASM			1
#define DES_BS				1
#define DES_BS_VECTOR			2
#define DES_BS_EXPAND			1
#define DES_BS_ALGORITHM_NAME		"64/64 BS MMX"

#define MD5_ASM				1
#define MD5_X2				0
#define MD5_IMM				1

#define BF_ASM				1
#define BF_SCALE			1

#define MMX_COEF			4
#define MMX_TYPE			" (SSE2 4x)"

#endif
