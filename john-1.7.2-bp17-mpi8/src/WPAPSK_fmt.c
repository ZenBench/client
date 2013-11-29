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
#include "sha.h"

#ifdef OSX
#undef MMX_COEF
#endif

#define FORMAT_LABEL			"wpapsk"
#define FORMAT_NAME			"WPA PSK"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"wpa-psk MMX"
#else
#define ALGORITHM_NAME			"pwa-psk SSE2"
#endif
#else
#define ALGORITHM_NAME			"wpa-psk"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		60
#define CIPHERTEXT_LENGTH		(128+400)

#define BINARY_SIZE			16
#define SHA_SIZE			20
#define SALT_SIZE			64

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (((i)&3)) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

// format : essid#MIC AA SPA snonce anonce keymic eapolframe
static struct fmt_tests wpapsk_tests[] = {
	{"somethingclever#c016873ee6bb01499d77bde7c5e7a4be 00026f01b8fb000c413f313e289f35c24325dda9e773a11cd0416a880622c3589a37886e318120a7e0ad68dd8a4b70c7b368bac5b4476a9e6071270d1d5734e484cf09ddd3f29966e20136de 0103005ffe010900200000000000000001289f35c24325dda9e773a11cd0416a880622c3589a37886e318120a7e0ad68dd", "family movie night"},
	{NULL}
};

#ifdef MMX_COEF
//static char saved_key[PLAINTEXT_LENGTH*MMX_COEF*2 + 1] __attribute__ ((aligned(16)));
static char crypt_key[64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned long total_len;
unsigned char opad[PLAINTEXT_LENGTH*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char ipad[PLAINTEXT_LENGTH*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char cursalt[SALT_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char dump[80*4*MMX_COEF] __attribute__((aligned(16)));
#else
//static char saved_key[PLAINTEXT_LENGTH + 1];
static char crypt_key[BINARY_SIZE+1];
static SHA_CTX ctx;
unsigned char opad[64];
unsigned char ipad[64];
unsigned char nopad[64];
unsigned char nipad[64];
unsigned char cursalt[SALT_SIZE];
unsigned char dump[SHA_SIZE];
#endif
unsigned char out[PLAINTEXT_LENGTH];

unsigned char DATA[12+64];
unsigned char nDATA[12+64+23+1];
unsigned char EAPOL[99];

static void wpapsk_init(void)
{
#ifdef MMX_COEF
	memset(crypt_key, 0, 64*MMX_COEF);
	memset(cursalt, 0, 64*MMX_COEF);
	crypt_key[GETPOS(BINARY_SIZE,0)] = 0x80;
	crypt_key[GETPOS(BINARY_SIZE,1)] = 0x80;
#if (MMX_COEF == 4)
	crypt_key[GETPOS(BINARY_SIZE,2)] = 0x80;
	crypt_key[GETPOS(BINARY_SIZE,3)] = 0x80;
#endif
#else
	memset(nipad, 0x36, 64);
	memset(nopad, 0x5C, 64);
	memset(EAPOL, 0, sizeof(EAPOL));
	strcpy(nDATA, "Pairwise key expansion");
#endif
}

static int valid(char *ciphertext)
{
	int pos, i;

	for(i=0;(i<strlen(ciphertext)) && (ciphertext[i]!='#');i++) ;
	if(i==strlen(ciphertext))
		return 0;
	pos = i+1;
	for (i = pos; i < BINARY_SIZE*2+pos; i++){
		if (!(  (('0' <= ciphertext[i])&&(ciphertext[i] <= '9')) ||
					(('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))  
					|| (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
			return 0;
	}
	return 1;
}

static void wpapsk_set_salt(void *salt) 
{
#ifdef MMX_COEF
	total_len = 0;
	while( ((unsigned char *)salt)[total_len] )
	{
		cursalt[GETPOS(total_len, 0)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 1)] = ((unsigned char *)salt)[total_len];
#if (MMX_COEF == 4)
		cursalt[GETPOS(total_len, 2)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 3)] = ((unsigned char *)salt)[total_len];
#endif
		total_len ++;
	}
	while( ((unsigned char *)salt)[total_len-4] )
	{
		cursalt[GETPOS(total_len, 0)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 1)] = ((unsigned char *)salt)[total_len];
#if (MMX_COEF == 4)
		cursalt[GETPOS(total_len, 2)] = ((unsigned char *)salt)[total_len];
		cursalt[GETPOS(total_len, 3)] = ((unsigned char *)salt)[total_len];
#endif
		total_len ++;
	}

	cursalt[GETPOS(total_len, 0)] = 0x80;
	cursalt[GETPOS(total_len, 1)] = 0x80;
#if (MMX_COEF == 4)
	cursalt[GETPOS(total_len, 2)] = 0x80;
	cursalt[GETPOS(total_len, 3)] = 0x80;
#endif
#else
	memcpy(cursalt, salt, SALT_SIZE);
#endif
}

static void wpapsk_set_key(char *key, int index) {
	int i;
	int len;
	
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

#ifdef MMX_COEF
	if(index==0)
	{
		memset(ipad, 0x36, 64*MMX_COEF);
		memset(opad, 0x5C, 64*MMX_COEF);
	}
	
	for(i=0;i<len;i++)
	{
		ipad[GETPOS(i, index)] = 0x36 ^ key[i];
		opad[GETPOS(i, index)] = 0x5C ^ key[i];
	}

	//saved_key[GETPOS(i, index)] = 0x80;
#else
	memset(ipad, 0x36, 64);
	memset(opad, 0x5C, 64);
	for(i=0;i<len;i++)
	{
		ipad[i] ^= key[i];
		opad[i] ^= key[i];
	}
#endif
}

static char *wpapsk_get_key(int index) {
	unsigned int i;
	for(i=0;i<PLAINTEXT_LENGTH;i++)
#ifdef MMX_COEF
		out[i] = ipad[ GETPOS(i, index) ] ^ 0x36;
#else
		out[i] = ipad[ i ] ^ 0x36;
#endif
	return out;
}

static int wpapsk_cmp_all(void *binary, int index) { 
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

static int wpapsk_cmp_exact(char *source, int count){
  return (1);
}

static int wpapsk_cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return wpapsk_cmp_all(binary, index);
#endif
}

/*
 * ça ne marche pas et ça m'a gonflé
 */

static void wpapsk_crypt_all(int count) {  
#ifdef MMX_COEF
	/*int i;*/
	printf("\n");
	dump_stuff_mmx(ipad, 64, 0);
	memcpy(dump, ipad, 64*MMX_COEF);
	shammx_nosizeupdate( dump, dump, 64);

	memcpy(dump, cursalt, 64*MMX_COEF);
	shammx_noinit_uniformsizeupdate(dump, dump, total_len + 64 );
	dump_stuff_mmx(dump, SHA_SIZE, 0);

	shammx_nosizeupdate( dump, opad, 64);
	shammx_noinit_uniformsizeupdate(dump, dump, SHA_SIZE + 64);
	dump_stuff_mmx(dump, SHA_SIZE, 0);

	return;
#else
	unsigned char dump[SHA_SIZE];
	unsigned char digest[SHA_SIZE];
	unsigned char ptk[20*4];
	unsigned int i,j;
	MD5_CTX md5ctx;
	
	//printf("\n");
	//first calculation - left part
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, ipad, 64 );
	SHA1_Update( &ctx, cursalt, strlen(cursalt) + 4 );
	SHA1_Final( dump, &ctx);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, opad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( dump, &ctx);
	memcpy(digest, dump, SHA_SIZE);
	for(i=1;i<4096;i++)
	{
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, ipad, 64 );
		SHA1_Update( &ctx, dump, SHA_SIZE );
		SHA1_Final( dump, &ctx);
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, opad, 64 );
		SHA1_Update( &ctx, dump, SHA_SIZE);
		SHA1_Final( dump, &ctx);
		for(j=0;j<SHA_SIZE;j++)
			digest[j] ^= dump[j];
	}
	//first calculation - right part
	cursalt[ strlen(cursalt) + 3 ] = 2;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, ipad, 64 );
	SHA1_Update( &ctx, cursalt, strlen(cursalt) + 4 );
	SHA1_Final( dump, &ctx);
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, opad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( dump, &ctx);
	memcpy(digest+SHA_SIZE, dump, 32-SHA_SIZE);
	for(i=1;i<4096;i++)
	{
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, ipad, 64 );
		SHA1_Update( &ctx, dump, SHA_SIZE );
		SHA1_Final( dump, &ctx);
		SHA1_Init( &ctx );
		SHA1_Update( &ctx, opad, 64 );
		SHA1_Update( &ctx, dump, SHA_SIZE);
		SHA1_Final( dump, &ctx);
		for(j=0;j<32-SHA_SIZE;j++)
			digest[j+SHA_SIZE] ^= dump[j];
	}
	//we now got pmk in digest,32
	//dump_stuff(digest, 32 );
	for(i=0;i<32;i++)
	{
		nipad[i] = 0x36 ^ digest[i];
		nopad[i] = 0x5c ^ digest[i];
	}
	//a hmac must be done with secret key pmk/32, and text "Pairwise key expansion",0,DATA,counter
	nDATA[23+64+12] = 0;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nipad, 64 );
	SHA1_Update( &ctx, nDATA, 22+1+12+64+1 );
	SHA1_Final( dump, &ctx );
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nopad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( ptk, &ctx);

	//seems not to be used ...
	/*
	nDATA[23+64+12] = 1;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nipad, 64 );
	SHA1_Update( &ctx, nDATA, 22+1+12+64+1 );
	SHA1_Final( dump, &ctx );
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nopad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( ptk + 20, &ctx);

	nDATA[23+64+12] = 2;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nipad, 64 );
	SHA1_Update( &ctx, nDATA, 22+1+12+64+1 );
	SHA1_Final( dump, &ctx );
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nopad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( ptk + 40, &ctx);

	nDATA[23+64+12] = 3;
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nipad, 64 );
	SHA1_Update( &ctx, nDATA, 22+1+12+64+1 );
	SHA1_Final( dump, &ctx );
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, nopad, 64 );
	SHA1_Update( &ctx, dump, SHA_SIZE);
	SHA1_Final( ptk + 60, &ctx);
	*/
	//we now have the ptk ...

	//now hmac md5 ...
	memset(nipad + 16, 0x36 , 16); 
	memset(nopad + 16, 0x5C , 16); 
	for(i=0;i<16;i++)
	{
		nipad[i] = 0x36 ^ ptk[i];
		nopad[i] = 0x5C ^ ptk[i];
	}
	MD5_Init( &md5ctx );
	MD5_Update( &md5ctx, nipad, 64 );
	MD5_Update( &md5ctx, EAPOL, sizeof(EAPOL) );
	MD5_Final ( dump, &md5ctx );
	MD5_Init( &md5ctx );
	MD5_Update( &md5ctx, nopad, 64 );
	MD5_Update( &md5ctx, dump, 16 );
	MD5_Final ( crypt_key, &md5ctx );
#endif
  
}

static void * wpapsk_binary(char *ciphertext) 
{
	static unsigned char realcipher[BINARY_SIZE];
	int i,pos;
	
	for(i=0;ciphertext[i]!='#';i++);
	pos=i+1;
	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2+pos])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1+pos])];
	}
	pos += i*2+1;
	i=0;
	while(ciphertext[pos]!=' ')
	{
		DATA[i] = atoi16[ARCH_INDEX(ciphertext[pos])]*16 + atoi16[ARCH_INDEX(ciphertext[1+pos])];
		i++;
		pos += 2;
	}
	memcpy(nDATA+23, DATA, 12+64);
	pos++;
	i=0;
	while(ciphertext[pos])
	{
		EAPOL[i] = atoi16[ARCH_INDEX(ciphertext[pos])]*16 + atoi16[ARCH_INDEX(ciphertext[1+pos])];
		i++;
		pos += 2;
	}

	return (void *)realcipher;
}

static void * wpapsk_salt(char *ciphertext)
{
	static unsigned char salt[SALT_SIZE];
	memset(salt, 0, SALT_SIZE);
	int i=0;
	while(ciphertext[i]!='#')
	{
		salt[i] = ciphertext[i];
		i++;
	}
	salt[i]=0;
	salt[i+1]=0;
	salt[i+2]=0;
	salt[i+3]=1;
	return salt;
}

struct fmt_main fmt_WPAPSK = {
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
		wpapsk_tests
	}, {
		wpapsk_init,
		valid,
		fmt_default_split,
		wpapsk_binary,
		wpapsk_salt,
		{
			fmt_default_binary_hash,
			fmt_default_binary_hash,
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		wpapsk_set_salt,
		wpapsk_set_key,
		wpapsk_get_key,
		fmt_default_clear_keys,
		wpapsk_crypt_all,
		{
			fmt_default_get_hash,
			fmt_default_get_hash,
			fmt_default_get_hash
		},
		wpapsk_cmp_all,
		wpapsk_cmp_one,
		wpapsk_cmp_exact
	}
};
