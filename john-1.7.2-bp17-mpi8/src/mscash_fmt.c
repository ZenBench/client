/*
 * Copyright (c) 2004 Simon Marechal
 * bartavelle@bandecon.com
 *
 * This is a plugin that adds Microsoft credential's cache hashing algorithm,
 * MS Cache Hash, a.k.a. MS Cash. This patch is invasive because john doesn't
 * support the use of the username easily within the current framework.
 * In order to get those hashes, use the CacheDump utility :
 *
 * http://www.cr0.net:8040/misc/cachedump.html
 *
 * It uses 
 * - smbencrypt.c Copyright (C) Andrew Tridgell 1997-1998
 * - md4.c, md4.h by Solar Designer
 *  
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md4.h"

#define FORMAT_LABEL			"mscash"
#define FORMAT_NAME			"M$ Cache Hash"
#define ALGORITHM_NAME			"mscash"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32

#define BINARY_SIZE			16
//max username size is 64, double for unicode "optimization"
#define SALT_SIZE			(64*2)
#define CIPHERTEXT_LENGTH		(BINARY_SIZE*2 + SALT_SIZE)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests mscash_tests[] = {
	{"M$test1#64cd29e36a8431a2b111378564a10631", "test1" },
	{"M$test2#ab60bdb4493822b175486810ac2abe63", "test2" },
	{"M$test3#14dd041848e12fc48c0aa7a416a4a00c", "test3" },
	{"M$test4#b945d24866af4b01a6d89b9d932a153c", "test4" },
	{NULL}
};

static char saved_key[PLAINTEXT_LENGTH + 1];
//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

static int salt_length; //the length of the current username
static unsigned short cur_salt[SALT_SIZE/2]; //current salt

extern void E_md4hash(unsigned char *passwd, unsigned char *p16);

static int valid(char *ciphertext)
{
	int i;
	int l;

	/*
	 * 2 cases
	 * 1 - it comes from the disk, and does not have M$ + salt
	 * 2 - it comes from memory, and has got M$ + salt + # + blah
	 */

	if (!memcmp(ciphertext, "M$", 2))
	{
		l = strlen(ciphertext) - PLAINTEXT_LENGTH;
		if(ciphertext[l-1]!='#')
			return 0;
	}
	else
	{
		if(strlen(ciphertext)!=PLAINTEXT_LENGTH)
			return 0;
		l = 0;
	}
	for (i = l; i < l + PLAINTEXT_LENGTH; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	
	return 1;
}

//salt is unicode, so let's say it's unsigned short
static void mscash_set_salt(void *salt) {
	salt_length = 0;
	while( ((unsigned char *)salt)[salt_length]!='#' )
	{
#if ARCH_LITTLE_ENDIAN
		cur_salt[salt_length] = ((unsigned char *)salt)[salt_length];
#else
		cur_salt[salt_length] = ((unsigned char *)salt)[salt_length] << 8;
#endif
		salt_length ++;
	}
	cur_salt[salt_length] = 0;
}

static void mscash_set_key(char *key, int index) {
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
}

static char *mscash_get_key(int index) {
    return saved_key;
}

static int mscash_cmp_all(void *binary, int index) { 
	int i=0;
	while(i<BINARY_SIZE)
	{
		if(((char *)binary)[i]!=((char *)crypt_key)[i])
			return 0;
		i++;
	}
	return 1;
}

static void mscash_crypt_all(int count) {  
	unsigned char buffer[BINARY_SIZE+SALT_SIZE];
	// get plaintext input in saved_key put it into ciphertext crypt_key
	
	//stage 1 : build nt hash of password
	E_md4hash(saved_key, buffer);

	//stage 2 : append cleartext to buffer
	memcpy(buffer+BINARY_SIZE, cur_salt, salt_length*2);

	//stage 3 : generate final hash and put it in crypt_key
	mdfour(crypt_key, buffer, BINARY_SIZE+salt_length*2);
}

static void * mscash_binary(char *ciphertext) 
{
	static unsigned char realcipher[BINARY_SIZE];
	int i;
	
	int l = strlen(ciphertext);
	for(i=0; i<BINARY_SIZE ;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l-BINARY_SIZE*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+l-BINARY_SIZE*2+1])];
	}
	return (void *)realcipher;
}

static void * mscash_get_salt(char * ciphertext)
{
	static unsigned char out[SALT_SIZE];
	int l;

	l = strlen(ciphertext);
	strncpy(out, ciphertext + 2, l - PLAINTEXT_LENGTH + 1);
	return out;
}

static int mscash_cmp_one(void *binary, int count){
	return (1);
}

static int mscash_cmp_exact(char *source, int count){
	return 1;
	//return (!memcmp(mscash_binary(source), crypt_key, BINARY_SIZE));
}

struct fmt_main fmt_mscash = {
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
		mscash_tests
	}, {
		fmt_default_init,
		valid,
		fmt_default_split,
		mscash_binary,
		mscash_get_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		mscash_set_salt,
		mscash_set_key,
		mscash_get_key,
		fmt_default_clear_keys,
		mscash_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		mscash_cmp_all,
		mscash_cmp_one,
		mscash_cmp_exact
	}
};
