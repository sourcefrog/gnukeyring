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
# define SWAP(n) (n)
#else
# define SWAP(n)							\
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
#endif

/* SHA initial values */

const UInt32 initsha1[5] =  {
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
SHA1_Block_ (const UInt32 *digin, UInt32 *buffer, UInt32 *digout)
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

SHA1_SECTION void
SHA1_Init (SHA_CTX *ctx)
{
    MemMove(ctx->dig, initsha1, sizeof(initsha1));
    ctx->len = ctx->lenHi = 0;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
SHA1_SECTION void
SHA1_Final (unsigned char *resbuf, SHA_CTX *ctx)
{
  /* Take yet unprocessed bytes into account.  */
  UInt16 bytes = ctx->len & (kSHA1BlockSize - 1);
  UInt32 *data;
  Char   *cdata;
#ifndef WORDS_BIGENDIAN
  int i;
#endif

  /* Now count remaining bytes.  */

  cdata = (char*) ctx->data;
  cdata[bytes++] = 0x80;
  if (bytes > 56) {
      MemSet(cdata + bytes, 64 - bytes, 0);
      data = ctx->data;
#ifndef WORDS_BIGENDIAN
      for (i = 0; i < 16; i++)
	  *data++ = SWAP(*data);
#endif
      SHA1_Block(ctx->dig, ctx->data, ctx->dig);
      MemSet(cdata, 56, 0);
  } else {
      MemSet(cdata + bytes, 56 - bytes, 0);
  }

  data = ctx->data;
#ifndef WORDS_BIGENDIAN
  for (i = 0; i < 14; i++)
      *data++ = SWAP(*data);
#endif

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->data[14] = (ctx->lenHi << 3) | (ctx->len >> 29);
  ctx->data[15] = ctx->len << 3;

  /* Process last bytes.  */
  SHA1_Block (ctx->dig, ctx->data, ctx->dig);

#ifndef WORDS_BIGENDIAN
  for (i = 0; i < 4; i++)
      ctx->dig[i] = SWAP (ctx->dig[i]);
#endif

  MemMove(resbuf, ctx->dig, sizeof(ctx->dig));
  /* Erase private data */
  MemSet(ctx, sizeof(ctx), 0);
}

SHA1_SECTION void
SHA1_Update (SHA_CTX *ctx, const unsigned char *buffer, unsigned long len)
{
    int i;
    UInt16 left_over = ctx->len & (kSHA1BlockSize - 1);
    UInt16 add = 64 - left_over;
    UInt32 *data;

    ctx->len += len;
    if (ctx->len < len)
	ctx->lenHi++;

    /* When we already have some bits in our internal buffer concatenate
       both inputs first.  */
    while (len >= add) {
	data = ctx->data;
	MemMove (((char*)data) + left_over, buffer, add);

	for (i = 0; i < 16; i++)
	    *data++ = SWAP(*data);
	SHA1_Block (ctx->dig, ctx->data, ctx->dig);
	buffer   += add;
	len      -= add;
	left_over = 0;
	add       = 64;
    }
    
    /* Move remaining bytes in internal buffer.  */
    if (len > 0)
	MemMove (((char*)ctx->data) + left_over, buffer, len);
}

/* Compute SHA1 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
SHA1_SECTION unsigned char *
SHA1(const unsigned char *buffer, unsigned long len, unsigned char *resblock)
{
  SHA_CTX ctx;

  /* Initialize the computation context.  */
  SHA1_Init (&ctx);

  /* Process whole buffer but last len % 64 bytes.  */
  SHA1_Update (&ctx, buffer, len);

  /* Put result in desired memory area.  */
  SHA1_Final (resblock, &ctx);

  return resblock;
}


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

    if (StrLen(passwd) > kSHA1BlockSize)
	SHA1(passwd, StrLen(passwd), (Char *) b.block);
    else
	MemMove(b.block, passwd, StrLen(passwd));

    data = b.block;
    for (i = 0; i < 16; i++)
	*data++ = SWAP(*data) ^ 0x36363636;
    SHA1_Block(initsha1, b.block, b.idig);

    /* Now prepare opad */
    data = b.block;
    for (i = 0; i < 16; i++)
	*data++ ^= (0x36363636 ^ 0x5c5c5c5c);
    SHA1_Block(initsha1, b.block, b.odig);

    for (k = 1; resultLen > 0; k++) {
	MemSet(b.block, sizeof(b.block), 0);
	MemMove(b.block, salt, kSaltSize);
	b.block[kSaltSize/4] = k;
	((unsigned char*) b.block)[kSaltSize + 4] = 0x80;
	b.block[15] = (sizeof(b.block) + kSaltSize + 4) * 8;
	SHA1_Block(b.idig, b.block, b.block);

#if kSaltSize + 4 > kSHA1HashSize
	MemSet(b.block + (kSHA1HashSize / 4), 
	       kSHA1BlockSize - kSHA1HashSize, 0);
#endif
	((unsigned char*) b.block)[kSHA1HashSize] = 0x80;
	b.block[15] = (sizeof(b.block) + sizeof(b.dig)) * 8;
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
#ifndef WORDS_BIGENDIAN
	for (i = 0; i < 5; i++)
	    b.dig[i] = SWAP(b.dig[i]);
#endif
	MemMove(result, b.dig, 
		kSHA1HashSize < resultLen ? kSHA1HashSize : resultLen);
	result    += kSHA1HashSize;
	resultLen -= kSHA1HashSize;
    }

    /* Now erase all buffers, they may contain passwords */
    MemSet(&b, sizeof(b), 0);
}

