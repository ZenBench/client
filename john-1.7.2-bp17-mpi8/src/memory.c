/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 1996-98 by Solar Designer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "arch.h"
#include "misc.h"
#include "memory.h"

unsigned int mem_saving_level = 0;

void *mem_alloc(size_t size)
{
	void *res;

	if (!size) return NULL;

	if (!(res = malloc(size))) {
		fprintf(stderr, "malloc: %s\n", strerror(ENOMEM));
		error();
	}

	return res;
}

void *mem_alloc_tiny(size_t size, size_t align)
{
	static unsigned long buffer, bufree = 0;
	unsigned long start, end;

#if ARCH_ALLOWS_UNALIGNED
	if (mem_saving_level > 2) align = MEM_ALIGN_NONE;
#endif

	start = buffer + --align; start &= ~align;
	end = start + size;

	if (bufree >= end - buffer) {
		bufree -= end - buffer;
		buffer = end;
	} else
	if (size + align <= MEM_ALLOC_SIZE && bufree <= MEM_ALLOC_MAX) {
		buffer = (unsigned long)mem_alloc(MEM_ALLOC_SIZE);
		bufree = MEM_ALLOC_SIZE;
		return mem_alloc_tiny(size, align + 1);
	} else
		start = ((unsigned long)
			mem_alloc(size + align) + align) & ~align;

	return (void *)start;
}

void *mem_alloc_copy(size_t size, size_t align, void *src)
{
	return memcpy(mem_alloc_tiny(size, align), src, size);
}

char *str_alloc_copy(char *src)
{
	size_t size;

	if (!src) return "";
	if (!*src) return "";

	size = strlen(src) + 1;
	return (char *)memcpy(mem_alloc_tiny(size, MEM_ALIGN_NONE), src, size);
}

void dump_stuff(unsigned char * x, unsigned int size)
{
	while(size--)
	{
		printf("%.2x", *x);
		x++;
	}
	printf("\n");
}

#ifdef MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )

void dump_stuff_mmx(unsigned char * buf, unsigned int size, unsigned int index)
{
	int i;
	for(i=0;i<size;i++)
	{
		if(!(i%4))
			printf(" ");
		printf("%.2x", buf[GETPOS(i, index)]);
	}
	printf("\n");
}
#endif
