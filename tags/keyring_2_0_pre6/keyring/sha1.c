/* sha1.c - Functions to compute SHA1 message digest of files or memory blocks
   according to the definition of SHA1 in RFC 1321 from April 1992.
   Copyright (C) 1995, 1996 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>, 1995.  */

#include "includes.h"

#define WORDS_BIGENDIAN 1

#ifdef WORDS_BIGENDIAN
#define MemMoveSwap(d,s,n) MemMove(d,s,n)
#else
static void
MemMoveSwap (void *dest, const void *src, unsigned int len)
{
    char *d = dest;
    char *s = src;
    while (len >= 4) {
	d[3] = s[0]; d[2] = s[1]; d[1] = s[2]; d[0] = s[3];
	d += 4;
	s += 4;
	len -= 4;
    }
    switch (len) {
    case 3:
	d[1] = s[2]; 
    case 2:
	d[2] = s[1]; 
    case 1:
	d[3] = s[0];
    case 0:
    }
}
#endif

/* SHA initial values */
/* This would be a const array, but unfortunately prc-tools just
 * produces illegal code.
 */
UInt32 initsha1[5] =  {
    0x67452301L,
    0xEFCDAB89L,
    0x98BADCFEL,
    0x10325476L,
    0xC3D2E1F0L
};

#if 0 /* This is now an assembler function */
/* The SHA f()-functions */

#define f1(x,y,z)   ( ( x & y ) | ( ~x & z ) )              /* Rounds  0-19 */
#define f2(x,y,z)   ( x ^ y ^ z )                           /* Rounds 20-39 */
#define f3(x,y,z)   ( ( x & y ) | ( x & z ) | ( y & z ) )   /* Rounds 40-59 */
#define f4(x,y,z)   ( x ^ y ^ z )                           /* Rounds 60-79 */

/* The SHA Mysterious Constants */

#define K1  0x5A827999L     /* Rounds  0-19 */
#define K2  0x6ED9EBA1L     /* Rounds 20-39 */
#define K3  0x8F1BBCDCL     /* Rounds 40-59 */
#define K4  0xCA62C1D6L     /* Rounds 60-79 */

/* It is unfortunate that C does not provide an operator for
   cyclic rotation.  Hope the C compiler is smart enough.  */
#define ROTATE(w, s) (((w) << (s)) | ((w) >> (32 - (s))))

/* Process 64 bytes of BUFFER, accumulating context into CTX. */

static SHA1_SECTION void
SHA1_Block (const UInt32 *digin, UInt32 *buffer, UInt32 *digout)
{
    UInt32 W[80];
    UInt32 A = digin[0];
    UInt32 B = digin[1];
    UInt32 C = digin[2];
    UInt32 D = digin[3];
    UInt32 E = digin[4];
    UInt32 t;
    int i;

    for (i = 0; i < 16; i++)
	W[i] = buffer[i];
    for (; i < 80; i++)
	W[i] = ROTATE(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16],1);
    
    /* Round 1.  */
    for (i = 0; i < 20; i++)
    {
	t = ROTATE(A, 5) + f1(B, C, D) + E + W[i] + K1;
	E = D;
	D = C;
	C = ROTATE(B,30);
	B = A;
	A = t;
    }

    /* Round 2.  */
    for (;i < 40; i++)
    {
	t = ROTATE(A, 5) + f2(B, C, D) + E + W[i] + K2;
	E = D;
	D = C;
	C = ROTATE(B,30);
	B = A;
	A = t;
    }

    /* Round 3.  */
    for (;i < 60; i++)
    {
	t = ROTATE(A, 5) + f3(B, C, D) + E + W[i] + K3;
	E = D;
	D = C;
	C = ROTATE(B,30);
	B = A;
	A = t;
    }

    /* Round 4.  */
    for (;i < 80; i++)
    {
	t = ROTATE(A, 5) + f4(B, C, D) + E + W[i] + K4;
	E = D;
	D = C;
	C = ROTATE(B,30);
	B = A;
	A = t;
    }

    /* Put checksum in context given as argument.  */
    digout[0] = digin[0] + A;
    digout[1] = digin[1] + B;
    digout[2] = digin[2] + C;
    digout[3] = digin[3] + D;
    digout[4] = digin[4] + E;
}
#endif

#if 0 /* This function is no longer used */

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in big endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
void 
SHA1(const unsigned char *buffer, unsigned long len, unsigned char *resblock)
{
    struct {
	UInt32 data[16];
	UInt32 dig[5];
    } b;
    UInt32 remaining = len;
    const UInt32 *digp = initsha1;

    /* When we already have some bits in our internal buffer concatenate
       both inputs first.  */
    while (remaining >= kSHA1BlockSize) {
	MemMoveSwap (b.data, buffer, kSHA1BlockSize);
	SHA1_Block (digp, b.data, b.dig);
	buffer    += kSHA1BlockSize;
	remaining -= kSHA1BlockSize;
	digp = b.dig;
    }
    
    /* Move remaining bytes in internal buffer.  */
    MemSet(b.data, sizeof(b.data));
    MemMoveSwap (b.data, buffer, remaining);
#ifdef WORDS_BIGENDIAN
    ((char*) b.data)[remaining] = 0x80;
#else
    ((char*) b.data)[remaining ^ 3] = 0x80;
#endif

    if ((len & 63) > 55) {
	SHA1_Block(digp, b.data, b.dig);
	digp = b.dig;
	MemSet(b.data, sizeof(b.data), 0);
    }

    /* Put the 64-bit file length in *bits* at the end of the buffer.  */
    /* We only put 32-bits as we are never called with 512MB blocks */
    b.data[15] = len << 3;
    
    /* Process last bytes.  */
    SHA1_Block (digp, b.data, b.dig);
    
    MemMoveSwap(resblock, b.dig, sizeof(b.dig));

    /* Erase private data */
    MemWipe(&b, sizeof(b));
}
#endif

SHA1_SECTION
void PwHash_PBKDF2(void* result, int resultLen, 
		   const Char *passwd, const Char *salt, int iter)
{
    struct {
	UInt32  idig[5];
	UInt32  odig[5];
	UInt32  block[16];
	UInt32  dig[5];
    } b;
    UInt32  *data;
    int     i, k;

    /* Prepare the HMAC buffers */
    MemSet(b.block, sizeof(b.block), 0);

    ErrNonFatalDisplayIf(StrLen(passwd) > kSHA1BlockSize,
			 __FUNCTION__ " password too long");
    MemMoveSwap(b.block, passwd, StrLen(passwd));

    data = b.block;
    for (i = 0; i < 16; i++)
	*data++ ^= 0x36363636;
    SHA1_Block(initsha1, b.block, b.idig);

    /* Now prepare opad */
    data = b.block;
    for (i = 0; i < 16; i++)
	*data++ ^= (0x36363636 ^ 0x5c5c5c5c);
    SHA1_Block(initsha1, b.block, b.odig);

    for (k = 1; resultLen > 0; k++) {
	MemSet(b.block, sizeof(b.block), 0);
	MemMoveSwap(b.block, salt, kSaltSize);
	b.block[kSaltSize/4] = k;
	b.block[kSaltSize/4 + 1] = 0x80000000;
	b.block[15] = (kSHA1BlockSize + kSaltSize + 4) * 8;
	SHA1_Block(b.idig, b.block, b.block);

#if kSaltSize + 4 > kSHA1HashSize
	MemSet(b.block + (kSHA1HashSize / 4), 
	       kSHA1BlockSize - kSHA1HashSize, 0);
#endif
	b.block[kSHA1HashSize / 4] = 0x80000000;
	b.block[15] = (kSHA1BlockSize + kSHA1HashSize) * 8;
	SHA1_Block(b.odig, b.block, b.block);
	MemMove(b.dig, b.block, sizeof(b.dig));

	i = iter;
	while (--i > 0) {
	    SHA1_Block(b.idig, b.block, b.block);
	    SHA1_Block(b.odig, b.block, b.block);
	    b.dig[0] ^= b.block[0];
	    b.dig[1] ^= b.block[1];
	    b.dig[2] ^= b.block[2];
	    b.dig[3] ^= b.block[3];
	    b.dig[4] ^= b.block[4];
	}
	MemMoveSwap(result, b.dig, 
		    kSHA1HashSize < resultLen ? kSHA1HashSize : resultLen);
	result    += kSHA1HashSize;
	resultLen -= kSHA1HashSize;
    }

    /* Now erase all buffers, they may contain passwords */
    MemWipe(&b, sizeof(b));
}
