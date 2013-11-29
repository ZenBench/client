/*
 * Copyright (c) 2004 Simon Marechal
 * simon.marechal@thales-security.com
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "des.h"

#define FORMAT_LABEL			"oracle"
#define FORMAT_NAME			"Oracle"
#define ALGORITHM_NAME			"oracle"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		16

#define BINARY_SIZE			8
#define SALT_SIZE			32
#define CIPHERTEXT_LENGTH		(BINARY_SIZE + SALT_SIZE)

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static struct fmt_tests oracle_tests[] = {
	{"O$SIMON#4F8BC1809CB2AF77", "A"},
	{"O$SIMON#183D72325548EF11", "THALES2" },
	{"O$SIMON#C4EB3152E17F24A4", "TST" },
	{"O$SYSTEM#9EEDFA0AD26C6D52", "THALES" },
	{NULL}
};

#if ARCH_LITTLE_ENDIAN
#define ENDIAN_SHIFT_L  << 8
#define ENDIAN_SHIFT_R  >> 8
#else
#define ENDIAN_SHIFT_L
#define ENDIAN_SHIFT_R
#endif

//stores the ciphertext for value currently being tested
static char crypt_key[BINARY_SIZE+1];

static unsigned char cur_salt[128 + 1]; //current salt
static unsigned char cur_key[128 + 1]; //current salt

static unsigned char deskey[8];
static unsigned char salt_iv[8];
static DES_key_schedule desschedule1;
static DES_key_schedule desschedule2;

static int salt_length;
static int key_length;

static int valid(char *ciphertext)
{
	int i;
	int l;

	/*
	 * 2 cases
	 * 1 - it comes from the disk, and does not have O$ + salt
	 * 2 - it comes from memory, and has got O$ + salt + # + blah
	 */

	if (!memcmp(ciphertext, "O$", 2))
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

static void oracle_init(void)
{
	deskey[0] = 0x01;
	deskey[1] = 0x23;
	deskey[2] = 0x45;
	deskey[3] = 0x67;
	deskey[4] = 0x89;
	deskey[5] = 0xab;
	deskey[6] = 0xcd;
	deskey[7] = 0xef;

	my_des_set_key(&deskey, &desschedule1);
}

static inline unsigned char upper(unsigned char c)
{
	if( (c>='a') && (c<='z'))
		return c+'A'-'a';
	return c;
}

static void oracle_set_salt(void *salt, int count) {
	salt_length = 0;

	memset(salt_iv, 0, 8);
	while ( (((unsigned short *)cur_salt)[salt_length] = upper(((unsigned char *)salt)[salt_length]) ENDIAN_SHIFT_L ))
		salt_length++;
}

static void oracle_set_key(char *key, int index) {
	key_length = 0;
	while( (((unsigned short *)cur_key)[key_length] = upper(key[key_length]) ENDIAN_SHIFT_L ))
		key_length++;
}

static char *oracle_get_key(int index) {
	static unsigned char out[PLAINTEXT_LENGTH];
	unsigned int i;
	for(i=0;i<key_length;i++)
		out[i] = ((unsigned short *)cur_key)[i] ENDIAN_SHIFT_R;
	out[i] = 0;
	return out;
}

static int oracle_cmp_all(void *binary, int index) { 
	int i=0;
	while(i<(BINARY_SIZE/sizeof(int)))
	{
		if(((int *)binary)[i]!=((int *)crypt_key)[i])
			return 0;
		i++;
	}
	return 1;
}

static void oracle_crypt_all(int count)  
{
	unsigned int l;

	
	l = (salt_length + key_length)*2;
	memcpy(crypt_key, salt_iv, 8);
	//that's the way john works ...
	memcpy(cur_salt + salt_length*2, cur_key, key_length * 2);
	my_des_ncbc_encrypt(cur_salt ,l , &desschedule1,(DES_cblock *) crypt_key);
	my_des_set_key((DES_cblock *)crypt_key, &desschedule2);
	memset(crypt_key, 0, 8);
	my_des_ncbc_encrypt(cur_salt, l , &desschedule2, (DES_cblock *)crypt_key);
}

static void * oracle_binary(char *ciphertext) 
{
	static unsigned char out3[BINARY_SIZE];
	int l;
	int i;
	l = strlen(ciphertext) - PLAINTEXT_LENGTH;
	for(i=0;i<BINARY_SIZE;i++) 
	{
		out3[i] = atoi16[ARCH_INDEX(ciphertext[i*2+l])]*16 
			+ atoi16[ARCH_INDEX(ciphertext[i*2+l+1])];
	}
	return out3;
}

static void * oracle_get_salt(char * ciphertext)
{
	static unsigned char out2[SALT_SIZE];
	int l;

	l = 2;
	while( ciphertext[l] && (ciphertext[l]!='#') )
	{
		out2[l-2] = ciphertext[l];
		l++;
	}
	out2[l-2] = 0;
	return out2;
}

static int oracle_cmp_one(void *binary, int count){
	return (1);
}

static int oracle_cmp_exact(char *source, int count){
	return 1;
}

static int binary_hash1(void * binary) { return (((unsigned int *)binary)[0] & 0xf); }
static int binary_hash2(void * binary) { return (((unsigned int *)binary)[0] & 0xff); }
static int binary_hash3(void * binary) { return (((unsigned int *)binary)[0] & 0xfff); }

static int get_hash1(int index) { return (((unsigned int *)crypt_key)[0] & 0xf); }
static int get_hash2(int index) { return (((unsigned int *)crypt_key)[0] & 0xff); }
static int get_hash3(int index) { return (((unsigned int *)crypt_key)[0] & 0xfff); }

struct fmt_main fmt_oracle = {
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
		FMT_8_BIT,
		oracle_tests
	}, {
		oracle_init,
		valid,
		fmt_default_split,
		oracle_binary,
		oracle_get_salt,
		{
			binary_hash1,
			binary_hash2,
			binary_hash3
		},
		fmt_default_salt_hash,
		oracle_set_salt,
		oracle_set_key,
		oracle_get_key,
		fmt_default_clear_keys,
		oracle_crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3
		},
		oracle_cmp_all,
		oracle_cmp_one,
		oracle_cmp_exact
	}
};
