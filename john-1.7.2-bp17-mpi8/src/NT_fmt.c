/*
 * NTLM patch for john version 0.3
 *
 * (C) 2001 Olle Segerdahl <olle@nxs.se>
 *
 * license: GPL <http://www.gnu.org/licenses/gpl.html>
 *
 * This file is based on code from John the Ripper,
 * Copyright (c) 1996-99 by Solar Designer
 *
 * performance enhancements by bartavelle@bandecon.com
 */

#include <string.h>

#include "arch.h"
#include "memory.h"
#include "common.h"
#include "formats.h"

#ifndef uchar
#define uchar unsigned char
#endif

#define FORMAT_LABEL			"nt"
#define FORMAT_NAME			"NT MD4"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		54
#define CIPHERTEXT_LENGTH		36


static struct fmt_tests tests[] = {
	{"$NT$b7e4b9022cd45f275334bbdb83bb5be5", "John the Ripper"},
	{"$NT$8846f7eaee8fb117ad06bdd830b7586c", "password"},
	{"$NT$0cb6948805f797bf2a82807973b89537", "test"},
	{"$NT$31d6cfe0d16ae931b73c59d7e0c089c0", ""},
	{NULL}
};

#define ALGORITHM_NAME			"TridgeMD4"

#define BINARY_SIZE			16
#define SALT_SIZE			0

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

uchar saved_plain[PLAINTEXT_LENGTH + 1];
uchar output[BINARY_SIZE + 1];

extern void E_md4hash(uchar *passwd, uchar *p16);


static int valid(char *ciphertext)
{
        char *pos;

	if (strncmp(ciphertext, "$NT$", 4)!=0) return 0;

        for (pos = &ciphertext[4]; atoi16[ARCH_INDEX(*pos)] != 0x7F; pos++);

        if (!*pos && pos - ciphertext == CIPHERTEXT_LENGTH)
		return 1;
        else
        	return 0;

}

static void *get_binary(char *ciphertext)
{
	static uchar binary[BINARY_SIZE];
	int i;

	ciphertext+=4;
	for (i=0; i<BINARY_SIZE; i++)
	{
 		binary[i] = (atoi16[ARCH_INDEX(ciphertext[i*2])])<<4;
 		binary[i] |= (atoi16[ARCH_INDEX(ciphertext[i*2+1])]);
	}

	return binary;
}

static int binary_hash_0(void *binary)
{
	return ((uchar *)binary)[0] & 0x0F;
}

static int binary_hash_1(void *binary)
{
	return ((uchar *)binary)[0];
}

static int binary_hash_2(void *binary)
{
	return (((uchar *)binary)[0] << 4) + (((uchar *)binary)[1] & 0x0F);
}

static int get_hash_0(int index)
{
	return output[0] & 0x0F;
}

static int get_hash_1(int index)
{
	return output[0];
}

static int get_hash_2(int index)
{
	return (output[0] << 4) + (output[1] & 0x0F);
}

static void crypt_all(int count)
{
	E_md4hash(saved_plain, output);
}

static int cmp_all(void *binary, int count)
{
	int i = 0;
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)output)[i])
			return 0;
		i++;
	}
	return 1;
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(output, get_binary(source), index);
}

static void set_salt(void *salt)
{
}

static void set_key(char *key, int index)
{
	strncpy(saved_plain, key, PLAINTEXT_LENGTH);
	saved_plain[PLAINTEXT_LENGTH] = 0;
}

static char *get_key(int index)
{
	return saved_plain;
}

struct fmt_main fmt_NT = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		SALT_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
		{
			binary_hash_0,
			binary_hash_1,
			binary_hash_2
		},
		fmt_default_salt_hash,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash_0,
			get_hash_1,
			get_hash_2
		},
		cmp_all,
		cmp_all,
		cmp_exact
	}
};
