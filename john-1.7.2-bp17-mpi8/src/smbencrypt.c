/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Modified by Jeremy Allison 1995.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#include <sys/types.h>
#include <string.h>
#include "arch.h"

#ifndef uchar
#define uchar unsigned char
#endif

#if !defined(uint16) && !defined(HAVE_UINT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define uint16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define uint16 unsigned short
#endif /* SIZEOF_SHORT != 4 */
#endif

#if !defined(int16) && !defined(HAVE_INT16_FROM_RPC_RPC_H)
#if (SIZEOF_SHORT == 4)
#define int16 __ERROR___CANNOT_DETERMINE_TYPE_FOR_INT16;
#else /* SIZEOF_SHORT != 4 */
#define int16 short
#endif /* SIZEOF_SHORT != 4 */
#endif

#include "byteorder.h"

extern void mdfour(unsigned char *out, unsigned char *in, int n);

/*
 * Convert a string into an NT UNICODE string.
 * Note that regardless of processor type 
 * this must be in intel (little-endian)
 * format.
 */
 
int _my_mbstowcs(int16 *dst, uchar *src, int len)
{
	int i;
 
	for(i = 0; i < len; i++) {
#if ARCH_LITTLE_ENDIAN
		dst[i] = src[i];
#else
		dst[i] = src[i] << 8;
#endif
	}
	return i;
}

/* 
 * Creates the MD4 Hash of the users password in NT UNICODE.
 */
 
void E_md4hash(uchar *passwd, uchar *p16)
{
	int len;
	int16 wpwd[129];
	
	/* Password cannot be longer than 128 characters */
	len = strlen((char *)passwd);
	if(len > 128)
		len = 128;
	/* Password must be converted to NT unicode */
	_my_mbstowcs(wpwd, passwd, len);
	wpwd[len] = 0; /* Ensure string is null terminated */
	/* Calculate length in bytes */
	//len = _my_wcslen(wpwd) * sizeof(int16);

	mdfour(p16, (unsigned char *)wpwd, len*2);
}

