/* md5.c - Functions to compute MD5 message digest of files or memory blocks
   according to the definition of MD5 in RFC 1321 from April 1992.
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
# ifdef __m68k__
static __inline__ UInt32 SWAP(UInt32 n)
{
    UInt32 res;
    __asm__("rol.w #8, %0\n\tswap %0\n\trol.w #8, %0" :
	    "=d" (res) : "0" (n));
    return res;
}
# else
#  define SWAP(n)							\
    (((n) << 24) | (((n) & 0xff00) << 8) | (((n) >> 8) & 0xff00) | ((n) >> 24))
# endif
#else
# define SWAP(n) (n)
#endif

const UInt32 initmd5[4] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};

#if 0

/* These are the four functions used in the four steps of the MD5 algorithm
   and defined in the RFC 1321.  The first function is a little bit optimized
   (as found in Colin Plumbs public domain implementation).  */
/* #define FF(b, c, d) ((b & c) | (~b & d)) */
#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

      /* Before we start, one word to the strange constants.
	 They are defined in RFC 1321 as

	 T[i] = (int) (4294967296.0 * fabs (sin (i))), i=1..64
       */

static char s1[4] = {  7, 12, 17, 22 };
static char s2[4] = {  5,  9, 14, 20 };
static char s3[4] = {  4, 11, 16, 23 };
static char s4[4] = {  6, 10, 15, 21 };

static const UInt32 round1[16] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
};
static const UInt32 round2[16] = {
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
};
static const UInt32 round3[16] = {
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
};
static const UInt32 round4[16] = {
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/* Process 64 bytes of BUFFER, accumulating context into CTX. */

MD5_SECTION void
MD5_Block (const UInt32 *digin, UInt32 *buffer, UInt32 *digout)
{
    UInt32 *words = buffer;
    UInt32 A = digin[0];
    UInt32 B = digin[1];
    UInt32 C = digin[2];
    UInt32 D = digin[3];
    UInt32 t;
    int i, j;

    /* First round: using the given function, the context and a constant
       the next context is computed.  Because the algorithms processing
       unit is a 32-bit word and it is determined to work on words in
       little endian byte order we perhaps have to change the byte order
       before the computation.  To reduce the work for the next steps
       we store the swapped words in place.  */
    
    /* It is unfortunate that C does not provide an operator for
       cyclic rotation.  Hope the C compiler is smart enough.  */
#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))
    
    /* Round 1.  */
    for (i = 0; i < 16; i++)
    {
	A += FF (B, C, D) + words[i] + round1[i];
	CYCLIC (A, s1[i&3]);
	A += B;
	t = D; D = C; C = B; B = A; A = t;
    }
    
    /* For the second to fourth round we have the possibly swapped words
       in BUFFER.  Redefine the macro to take an additional first
       argument specifying the function to use.  */
    
    for (i = 0, j = 1; i < 16; i++, j += 5)
    {
	A += FG (B, C, D) + buffer[j & 15] + round2[i];
	CYCLIC (A, s2[i&3]);
	A += B;
	t = D; D = C; C = B; B = A; A = t;
    }
    for (i = 0, j = 5; i < 16; i++, j += 3)
    {
	A += FH (B, C, D) + buffer[j & 15] + round3[i];
	CYCLIC (A, s3[i&3]);
	A += B;
	t = D; D = C; C = B; B = A; A = t;
    }
    for (i = 0, j = 0; i < 16; i++, j += 7)
    {
	A += FI (B, C, D) + buffer[j & 15] + round4[i];
	CYCLIC (A, s4[i&3]);
	A += B;
	t = D; D = C; C = B; B = A; A = t;
    }
    
    /* Put checksum in context given as argument.  */
    digout[0] = digin[0] + A;
    digout[1] = digin[1] + B;
    digout[2] = digin[2] + C;
    digout[3] = digin[3] + D;
}
#endif

/* Initialize structure containing state of computation.
   (RFC 1321, 3.3: Step 3)  */
MD5_SECTION void
MD5_Init (MD5_CTX *ctx)
{
    MemMove(ctx->dig, initmd5, sizeof(initmd5));

    ctx->len = ctx->lenHi = 0;
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.

   IMPORTANT: On some systems it is required that RESBUF is correctly
   aligned for a 32 bits value.  */
MD5_SECTION void
MD5_Final (unsigned char *resbuf, MD5_CTX *ctx)
{
  /* Take yet unprocessed bytes into account.  */
  UInt16 bytes = ctx->len & (kMD5BlockSize - 1);
  UInt32 *data;
  Char   *cdata;
  int i;

  /* Now count remaining bytes.  */

  cdata = (char*) ctx->data;
  cdata[bytes++] = 0x80;
  if (bytes > 56) {
      MemSet(cdata + bytes, 64 - bytes, 0);
      data = ctx->data;
      for (i = 0; i < 16; i++)
	  *data++ = SWAP(*data);
      MD5_Block(ctx->dig, ctx->data, ctx->dig);
      MemSet(cdata, 56, 0);
  } else {
      MemSet(cdata + bytes, 56 - bytes, 0);
  }

  data = ctx->data;
  for (i = 0; i < 14; i++)
      *data++ = SWAP(*data);

  /* Put the 64-bit file length in *bits* at the end of the buffer.  */
  ctx->data[14] = ctx->len << 3;
  ctx->data[15] = (ctx->lenHi << 3) | (ctx->len >> 29);

  /* Process last bytes.  */
  MD5_Block (ctx->dig, ctx->data, ctx->dig);

#ifdef WORDS_BIGENDIAN
  for (i = 0; i < 4; i++)
      ctx->dig[i] = SWAP (ctx->dig[i]);
#endif

  MemMove(resbuf, ctx->dig, sizeof(ctx->dig));
}

/* Compute MD5 message digest for LEN bytes beginning at BUFFER.  The
   result is always in little endian byte order, so that a byte-wise
   output yields to the wanted ASCII representation of the message
   digest.  */
MD5_SECTION unsigned char *
MD5 (unsigned char *buffer, unsigned long len, unsigned char *resblock)
{
    MD5_CTX ctx;
    
    /* Initialize the computation context.  */
    MD5_Init (&ctx);
    
    /* Process whole buffer but last len % 64 bytes.  */
    MD5_Update (&ctx, buffer, len);
    
    /* Put result in desired memory area.  */
    MD5_Final (resblock, &ctx);

    return resblock;
}


MD5_SECTION void
MD5_Update (MD5_CTX *ctx, unsigned char *buffer, unsigned long len)
{
    int i;
    UInt16 left_over = ctx->len & (kMD5BlockSize - 1);
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
	MD5_Block (ctx->dig, ctx->data, ctx->dig);
	buffer   += add;
	len      -= add;
	left_over = 0;
	add       = 64;
    }
    
    /* Move remaining bytes in internal buffer.  */
    if (len > 0)
	MemMove (((char*)ctx->data) + left_over, buffer, len);
}

#if 0
MD5_SECTION
void HMAC_MD5_PBKDF2(char* result, int resultLen,
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
    MemMove(b.block, passwd, StrLen(passwd));
    data = b.block;
    for (i = 0; i < 16; i++) {
	*data++ = SWAP(*data) ^ 0x36363636;
    }
    MD5_Block(initmd5, b.block, b.idig);

    /* Now prepare opad */
    data = b.block;
    for (i = 0; i < 16; i++) {
	*data++ ^= (0x36363636 ^ 0x5c5c5c5c);
    }
    MD5_Block(initmd5, b.block, b.odig);

    for (k = 1; resultLen > 0; k++) {
	MemSet(b.block, sizeof(b.block), 0);
	for (i = 0; i < kSaltSize / 4; i++) {
	    b.block[i] = SWAP(salt[i]);
	}
	b.block[i] = k;
	b.block[i+1] = 0x80;
	b.block[14] = (sizeof(b.block) + kSaltSize + 4) * 8;
	MD5_Block(b.idig, b.block, b.block);
	
	MemMove(b.dig, b.block, sizeof(b.dig));
	
#if kSaltSize + 4 > kMD5HashSize
	MemSet(b.block + (kMD5HashSize / 4), 
	       kMD5BlockSize - kMD5HashSize, 0);
#endif
	b.block[kMD5HashSize] = 0x80;
	b.block[14] = (sizeof(b.block) + sizeof(b.dig)) * 8;

	MD5_Block(b.odig, b.block, b.block);
	
	while (--iter > 0) {
	    MD5_Block(b.idig, b.block, b.block);
	    MD5_Block(b.odig, b.block, b.block);
	    b.dig[0] ^= b.block[0];
	    b.dig[1] ^= b.block[1];
	    b.dig[2] ^= b.block[2];
	    b.dig[3] ^= b.block[3];
	}
#ifdef WORDS_BIGENDIAN
	for (i = 0; i < 4; i++)
	    b.dig[i] = SWAP(b.dig[i]);
#endif
	MemMove(result, b.dig, sizeof(b.dig));
	result    += kMD5HashSize;
	resultLen -= kMD5HashSize;
    }

    /* Now erase all buffers, they may contain passwords */
    MemWipe(&b, sizeof(b));
}
#endif

#if 0
MD5_SECTION void TestMD5(void) {
    UInt32  odig[4];
    UInt32  block[16];
    Char out[100];

    MemSet(block, sizeof(block), 0);
    block[0] = 0x80;
    block[14] = 0;
    MD5_Block(initmd5, block, odig);
    odig[0] = SWAP(odig[0]);
    odig[1] = SWAP(odig[1]);
    odig[2] = SWAP(odig[2]);
    odig[3] = SWAP(odig[3]);
    StrPrintF(out, "MD5\n%08lx %08lx %08lx %08lx",
	      odig[ 0],odig[ 1],odig[ 2],odig[ 3]);
    //FrmCustomAlert(CryptoErrorAlert, out, "", "");
}
#endif
