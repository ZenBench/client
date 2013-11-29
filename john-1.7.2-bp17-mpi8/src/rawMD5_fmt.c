/*
 * Copyright (c) 2004 bartavelle
 * bartavelle@bandecon.com
 *
 * Simple MD5 hashes cracker
 * It uses the Solar Designer's md5 implementation
 * 
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#ifdef OSX
#undef MMX_COEF
#endif

#define FORMAT_LABEL			"raw-md5"
#define FORMAT_NAME			"Raw MD5"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"raw-md5 MMX"
#else
#define ALGORITHM_NAME			"raw-md5 SSE2"
#endif
#else
#define ALGORITHM_NAME			"raw-md5"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			16
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + (i& (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests rawmd5_tests[] = {
	{"5a105e8b9d40e1329780d62ea2265d8a", "test1"},
	{"ad0234829205b9033196ba818f7a872b", "test2"},
	{"8ad8757baa8564dc136c1e07507f4a98", "test3"},
	{"86985e105f79b95d6bc918fb45ec7727", "test4"},
	{NULL}
};

#ifdef MMX_COEF
static char saved_key[PLAINTEXT_LENGTH*MMX_COEF*2 + 1] __attribute__ ((aligned(16)));
static char crypt_key[BINARY_SIZE*MMX_COEF+1] __attribute__ ((aligned(16)));
unsigned long rmd5_total_len;
unsigned char rmd5_out[PLAINTEXT_LENGTH];
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static char crypt_key[BINARY_SIZE+1];
static MD5_CTX ctx;
#endif

static int valid(char *ciphertext)
{
	int i;

	if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
	for (i = 0; i < CIPHERTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void rawmd5_set_salt(void *salt) { }

static void rawmd5_set_key(char *key, int index) {
#ifdef MMX_COEF
	int len;
	int i;
	
	if(index==0)
	{
		rmd5_total_len = 0;
		memset(saved_key, 0, PLAINTEXT_LENGTH*MMX_COEF);
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	rmd5_total_len += len << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS(i, index)] = 0x80;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *rawmd5_get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;
	
	s = (rmd5_total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
	for(i=0;i<s;i++)
		rmd5_out[i] = saved_key[ GETPOS(i, index) ];
	rmd5_out[i] = 0;
	return rmd5_out;
#else
	return saved_key;
#endif
}

static int rawmd5_cmp_all(void *binary, int index) { 
	int i=0;
#ifdef MMX_COEF
	while(i< (BINARY_SIZE/4) )
	{
		if (
			( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
			&& ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#endif
		)
			return 0;
		i++;
	}
#else
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
#endif
	return 1;
}

static int rawmd5_cmp_exact(char *source, int count){
  return (1);
}

static int rawmd5_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return rawmd5_cmp_all(binary, index);
#endif
}

static void rawmd5_crypt_all(int count) {  
  // get plaintext input in saved_key put it into ciphertext crypt_key
#ifdef MMX_COEF
	mdfivemmx(crypt_key, saved_key, rmd5_total_len);
#else
	MD5_Init( &ctx );
	MD5_Update( &ctx, saved_key, strlen( saved_key ) );
	MD5_Final( crypt_key, &ctx);
#endif
  
}

static void * rawmd5_binary(char *ciphertext) 
{
	static char realcipher[BINARY_SIZE];
	int i;
	
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

static int get_hash1(int index)
{
#ifdef MMX_COEF
	return (((unsigned long *)crypt_key)[index] & 0xf);
#else
	return (((unsigned int *)crypt_key)[0] & 0xf);
#endif
}
static int get_hash2(int index)
{
#ifdef MMX_COEF
	return (((unsigned long *)crypt_key)[index] & 0xff);
#else
	return (((unsigned int *)crypt_key)[0] & 0xff);
#endif
}
static int get_hash3(int index)
{
#ifdef MMX_COEF
	return (((unsigned long *)crypt_key)[index] & 0xfff);
#else
	return (((unsigned int *)crypt_key)[0] & 0xfff);
#endif
}

static int binary_hash1(void * binary) { return (((unsigned int *)binary)[0] & 0xf); }
static int binary_hash2(void * binary) { return (((unsigned int *)binary)[0] & 0xff); }
static int binary_hash3(void * binary) { return (((unsigned int *)binary)[0] & 0xfff); }

struct fmt_main fmt_rawMD5 = {
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
		rawmd5_tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		rawmd5_binary,
		fmt_default_salt,
		{
			binary_hash1,
			binary_hash2,
			binary_hash3
		},
		fmt_default_salt_hash,
		rawmd5_set_salt,
		rawmd5_set_key,
		rawmd5_get_key,
		fmt_default_clear_keys,
		rawmd5_crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3
		},
		rawmd5_cmp_all,
		rawmd5_cmp_one,
		rawmd5_cmp_exact
	}
};
