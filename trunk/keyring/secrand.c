/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 *
 * GNU Keyring -- store passwords securely on a handheld
 * Copyright (C) 2001 Jochen Hoenicke <jochen@gnu.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/* Parts of this code are taken from the linux random device driver:
 * 
 * Copyright Theodore Ts'o, 1994, 1995, 1996, 1997, 1998.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * (now, with legal B.S. out of the way.....) 
 * 
 * This routine gathers environmental noise from device drivers, etc.,
 * and returns good random numbers, suitable for cryptographic use.
 * Besides the obvious cryptographic uses, these numbers are also good
 * for seeding TCP sequence numbers, and other places where it is
 * desirable to have numbers which are not only random, but hard to
 * predict by an attacker.
 *
 * Theory of operation
 * ===================
 * 
 * Computers are very predictable devices.  Hence it is extremely hard
 * to produce truly random numbers on a computer --- as opposed to
 * pseudo-random numbers, which can easily generated by using a
 * algorithm.  Unfortunately, it is very easy for attackers to guess
 * the sequence of pseudo-random number generators, and for some
 * applications this is not acceptable.  So instead, we must try to
 * gather "environmental noise" from the computer's environment, which
 * must be hard for outside attackers to observe, and use that to
 * generate random numbers.  In a Unix environment, this is best done
 * from inside the kernel.
 * 
 * Sources of randomness from the environment include inter-keyboard
 * timings, inter-interrupt timings from some interrupts, and other
 * events which are both (a) non-deterministic and (b) hard for an
 * outside observer to measure.  Randomness from these sources are
 * added to an "entropy pool", which is mixed using a CRC-like function.
 * This is not cryptographically strong, but it is adequate assuming
 * the randomness is not chosen maliciously, and it is fast enough that
 * the overhead of doing it on every interrupt is very reasonable.
 * As random bytes are mixed into the entropy pool, the routines keep
 * an *estimate* of how many bits of randomness have been stored into
 * the random number generator's internal state.
 * 
 * When random bytes are desired, they are obtained by taking the SHA
 * hash of the contents of the "entropy pool".  The SHA hash avoids
 * exposing the internal state of the entropy pool.  It is believed to
 * be computationally infeasible to derive any useful information
 * about the input of SHA from its output.  Even if it is possible to
 * analyze SHA in some clever way, as long as the amount of data
 * returned from the generator is less than the inherent entropy in
 * the pool, the output data is totally unpredictable.  For this
 * reason, the routine decreases its internal estimate of how many
 * bits of "true randomness" are contained in the entropy pool as it
 * outputs random numbers.
 * 
 * If this estimate goes to zero, the routine can still generate
 * random numbers; however, an attacker may (at least in theory) be
 * able to infer the future output of the generator from prior
 * outputs.  This requires successful cryptanalysis of SHA, which is
 * not believed to be feasible, but there is a remote possibility.
 * Nonetheless, these numbers should be useful for the vast majority
 * of purposes.
 * 
 * Acknowledgements:
 * =================
 *
 * Ideas for constructing this random number generator were derived
 * from Pretty Good Privacy's random number generator, and from private
 * discussions with Phil Karn.  Colin Plumb provided a faster random
 * number generator, which speed up the mixing function of the entropy
 * pool, taken from PGPfone.  Dale Worley has also contributed many
 * useful ideas and suggestions to improve this driver.
 * 
 * Any flaws in the design are solely my responsibility, and should
 * not be attributed to the Phil, Colin, or any of authors of PGP.
 * 
 * The code for SHA transform was taken from Peter Gutmann's
 * implementation, which has been placed in the public domain.
 * The code for MD5 transform was taken from Colin Plumb's
 * implementation, which has been placed in the public domain.  The
 * MD5 cryptographic checksum was devised by Ronald Rivest, and is
 * documented in RFC 1321, "The MD5 Message Digest Algorithm".
 * 
 * Further background information on this topic may be obtained from
 * RFC 1750, "Randomness Recommendations for Security", by Donald
 * Eastlake, Steve Crocker, and Jeff Schiller.
 */

#include <PalmOS.h>
#include "keyring.h"
#include "crypto.h"
#include "secrand.h"
#include "uiutil.h"
#include "resource.h"

/*
 * Configuration information
 */
#define ROTATE_PARANOIA

#define POOLWORDS 64    /* Power of 2 - note that this is 32-bit words */
#define POOLBITS (POOLWORDS*32)

/*
 * The pool is stirred with a primitive polynomial of degree POOLWORDS
 * over GF(2).  The taps for various sizes are defined below.  They are
 * chosen to be evenly spaced (minimum RMS distance from evenly spaced;
 * the numbers in the comments are a scaled squared error sum) except
 * for the last tap, which is 1 to get the twisting happening as fast
 * as possible.
 */
#if POOLWORDS == 2048	/* 115 x^2048+x^1638+x^1231+x^819+x^411+x^1+1 */
#define TAP1	1638
#define TAP2	1231
#define TAP3	819
#define TAP4	411
#define TAP5	1
#elif POOLWORDS == 1024	/* 290 x^1024+x^817+x^615+x^412+x^204+x^1+1 */
/* Alt: 115 x^1024+x^819+x^616+x^410+x^207+x^2+1 */
#define TAP1	817
#define TAP2	615
#define TAP3	412
#define TAP4	204
#define TAP5	1
#elif POOLWORDS == 512	/* 225 x^512+x^411+x^308+x^208+x^104+x+1 */
/* Alt: 95 x^512+x^409+x^307+x^206+x^102+x^2+1
 *      95 x^512+x^409+x^309+x^205+x^103+x^2+1 */
#define TAP1	411
#define TAP2	308
#define TAP3	208
#define TAP4	104
#define TAP5	1
#elif POOLWORDS == 256	/* 125 x^256+x^205+x^155+x^101+x^52+x+1 */
#define TAP1	205
#define TAP2	155
#define TAP3	101
#define TAP4	52
#define TAP5	1
#elif POOLWORDS == 128	/* 105 x^128+x^103+x^76+x^51+x^25+x+1 */
/* Alt: 70 x^128+x^103+x^78+x^51+x^27+x^2+1 */
#define TAP1	103
#define TAP2	76
#define TAP3	51
#define TAP4	25
#define TAP5	1
#elif POOLWORDS == 64	/* 15 x^64+x^52+x^39+x^26+x^14+x+1 */
#define TAP1	52
#define TAP2	39
#define TAP3	26
#define TAP4	14
#define TAP5	1
#elif POOLWORDS == 32	/* 15 x^32+x^26+x^20+x^14+x^7+x^1+1 */
#define TAP1	26
#define TAP2	20
#define TAP3	14
#define TAP4	7
#define TAP5	1
#elif POOLWORDS & (POOLWORDS-1)
#error POOLWORDS must be a power of 2
#else
#error No primitive polynomial available for chosen POOLWORDS
#endif

/*
 * For the purposes of better mixing, we use the CRC-32 polynomial as
 * well to make a twisted Generalized Feedback Shift Reigster
 *
 * (See M. Matsumoto & Y. Kurita, 1992.  Twisted GFSR generators.  ACM
 * Transactions on Modeling and Computer Simulation 2(3):179-194.
 * Also see M. Matsumoto & Y. Kurita, 1994.  Twisted GFSR generators
 * II.  ACM Transactions on Mdeling and Computer Simulation 4:254-266)
 *
 * Thanks to Colin Plumb for suggesting this.
 * We have not analyzed the resultant polynomial to prove it primitive;
 * in fact it almost certainly isn't.  Nonetheless, the irreducible factors
 * of a random large-degree polynomial over GF(2) are more than large enough
 * that periodicity is not a concern.
 *
 * The input hash is much less sensitive than the output hash.  All that
 * we want of it is that it be a good non-cryptographic hash; i.e. it
 * not produce collisions when fed "random" data of the sort we expect
 * to see.  As long as the pool state differs for different inputs, we
 * have preserved the input entropy and done a good job.  The fact that an
 * intelligent attacker can construct inputs that will produce controlled
 * alterations to the pool's state is not important because we don't
 * consider such inputs to contribute any randomness.
 * The only property we need with respect to them is
 * that the attacker can't increase his/her knowledge of the pool's state.
 * Since all additions are reversible (knowing the final state and the
 * input, you can reconstruct the initial state), if an attacker has
 * any uncertainty about the initial state, he/she can only shuffle that
 * uncertainty about, but never cause any collisions (which would
 * decrease the uncertainty).
 *
 * The chosen system lets the state of the pool be (essentially) the input
 * modulo the generator polymnomial.  Now, for random primitive polynomials,
 * this is a universal class of hash functions, meaning that the chance
 * of a collision is limited by the attacker's knowledge of the generator
 * polynomail, so if it is chosen at random, an attacker can never force
 * a collision.  Here, we use a fixed polynomial, but we *can* assume that
 * ###--> it is unknown to the processes generating the input entropy. <-###
 * Because of this important property, this is a good, collision-resistant
 * hash; hash collisions will occur no more often than chance.
 */

/*
 * The minimum number of bits to release a "wait on input".  Should
 * probably always be 8, since a /dev/random read can return a single
 * byte.
 */
#define WAIT_INPUT_BITS 8
/* 
 * The limit number of bits under which to release a "wait on
 * output".  Should probably always be the same as WAIT_INPUT_BITS, so
 * that an output wait releases when and only when a wait on input
 * would block.
 */
#define WAIT_OUTPUT_BITS WAIT_INPUT_BITS

/* There is actually only one of these, globally. */
typedef struct {
	unsigned add_ptr;
#ifdef ROTATE_PARANOIA	
	int input_rotate;
#endif
	UInt32 pool[POOLWORDS];
} Secrand_BucketType;

#define k_SecrandPrefId 'SR'
#define k_SecrandVersion 1

static Secrand_BucketType g_RandomState;

static inline UInt32 rotate_left(int i, UInt32 word)
{
    return (word << i) | (word >> (32 - i));
}

/*
 * This function adds a byte into the entropy "pool".  It does not
 * update the entropy estimate.  The caller must do this if appropriate.
 *
 * This function is tuned for speed above most other considerations.
 *
 * The pool is stirred with a primitive polynomial of the appropriate degree,
 * and then twisted.  We twist by three bits at a time because it's
 * cheap to do so and helps slightly in the expected case where the
 * entropy is concentrated in the low-order bits.
 */
#define MASK(x) ((x) & (POOLWORDS-1))	/* Convenient abreviation */
static void Secrand_AddEntropyWords(UInt32 x, UInt32 y)
{
    static UInt32 const twist_table[8] = {
	0, 0x3b6e20c8, 0x76dc4190, 0x4db26158,
	0xedb88320, 0xd6d6a3e8, 0x9b64c2b0, 0xa00ae278 };
    unsigned i, j;
    
    i = MASK(g_RandomState.add_ptr - 2);	/* i is always even */
    g_RandomState.add_ptr = i;
    
#ifdef ROTATE_PARANOIA
    j = g_RandomState.input_rotate + 7;
    if (!i)
	j += 7;
    g_RandomState.input_rotate = j &= 31;
    
    x = rotate_left(j, x);
    y = rotate_left(j, y);
#endif

    /*
     * XOR in the various taps.  Even though logically, we compute
     * x and then compute y, we read in y then x order because most
     * caches work slightly better with increasing read addresses.
     * If a tap is even then we can use the fact that i is even to
     * avoid a masking operation.  Every polynomial has at least one
     * even tap, so j is always used.
     */
#if TAP1 & 1
    y ^= g_RandomState.pool[MASK(i+TAP1)];
    x ^= g_RandomState.pool[MASK(i+TAP1+1)];
#else
    j = MASK(i+TAP1);
    y ^= g_RandomState.pool[j];
    x ^= g_RandomState.pool[j+1];
#endif
#if TAP2 & 1
    y ^= g_RandomState.pool[MASK(i+TAP2)];
    x ^= g_RandomState.pool[MASK(i+TAP2+1)];
#else
    j = MASK(i+TAP2);
    y ^= g_RandomState.pool[j];
    x ^= g_RandomState.pool[j+1];
#endif
#if TAP3 & 1
    y ^= g_RandomState.pool[MASK(i+TAP3)];
    x ^= g_RandomState.pool[MASK(i+TAP3+1)];
#else
    j = MASK(i+TAP3);
    y ^= g_RandomState.pool[j];
    x ^= g_RandomState.pool[j+1];
#endif
#if TAP4 & 1
    y ^= g_RandomState.pool[MASK(i+TAP4)];
    x ^= g_RandomState.pool[MASK(i+TAP4+1)];
#else
    j = MASK(i+TAP4);
    y ^= g_RandomState.pool[j];
    x ^= g_RandomState.pool[j+1];
#endif
#if TAP5 == 1
    /* We need to pretend to write pool[i+1] before computing y */
    x ^= g_RandomState.pool[MASK(i+2)];
    x ^= g_RandomState.pool[i+1];
    y ^= g_RandomState.pool[i+1] = x = (x >> 3) ^ twist_table[x & 7];
    y ^= g_RandomState.pool[i];
    g_RandomState.pool[i] = (y >> 3) ^ twist_table[y & 7];
#else
#if TAP5 & 1
    y ^= g_RandomState.pool[MASK(i+TAP5)];
    x ^= g_RandomState.pool[MASK(i+TAP5+1)];
#else
    j = MASK(i+TAP5);
    y ^= g_RandomState.pool[j];
    x ^= g_RandomState.pool[j+1];
#endif

    y ^= g_RandomState.pool[i];
    x ^= g_RandomState.pool[i+1];
    g_RandomState.pool[i] = (y >> 3) ^ twist_table[y & 7];
    g_RandomState.pool[i+1] = (x >> 3) ^ twist_table[x & 7];
#endif
}

/*
 * We store the unlocked session key in a temporary database
 * not marked for backup.
 */
void Secrand_Init(void)
{
    Int16 version;
    Int16 size = sizeof(g_RandomState);
    
    version = PrefGetAppPreferences(kKeyringCreatorID, k_SecrandPrefId,
				    &g_RandomState, &size, false);

    if (version != k_SecrandVersion || size != sizeof(g_RandomState)) {
	/* We have to initialize g_RandomState ourself.  We don't
	 * initialize the pool, since clearing it would only diminish
	 * entropy.
	 */
	g_RandomState.add_ptr = 0;
	g_RandomState.input_rotate = 0;
    }
    Secrand_AddEntropyWords(TimGetTicks(), TimGetSeconds());
}

/*
 * We store the entropy pool in the application preferences.
 */
void Secrand_Close(void)
{
    PrefSetAppPreferences(kKeyringCreatorID, 
			  k_SecrandPrefId, k_SecrandVersion,
			  &g_RandomState, sizeof(g_RandomState), false);
}

/*
 * This function adds entropy to the entropy "pool" from an event.
 */
void Secrand_AddEventRandomness(EventType *ev)
{
    UInt32 *rand = (UInt32 *) ev;
    int i = sizeof(EventType) / sizeof(UInt32);
    
    Secrand_AddEntropyWords(TimGetTicks(), TimGetSeconds());
    while (i-- > 0) {
	Secrand_AddEntropyWords(rand[0], rand[1]);
	rand += 2;
    }
}

#define HASH_BUFFER_SIZE (kMD5HashSize / (2 * sizeof(UInt32)))

/*
 * This function extracts randomness from the "entropy pool", and
 * returns it in a buffer.
 */
static void Secrand_ExtractEntropy(UInt32 buf[HASH_BUFFER_SIZE])
{
    UInt32 tmp[2 * HASH_BUFFER_SIZE];
    Char *digest = (Char *)tmp;
    Err err;
    UInt16 i;

    Secrand_AddEntropyWords(TimGetTicks(), TimGetSeconds());
    err = EncDigestMD5((UInt8 *)g_RandomState.pool, POOLWORDS * 4, digest);
    if (err)
	UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);

    /*
     * The following code does two separate things that happen
     * to both work two words at a time, so are convenient
     * to do together.
     *
     * First, this feeds the output back into the pool so
     * that the next call will return different results.
     * Any perturbation of the pool's state would do, even
     * changing one bit, but this mixes the pool nicely.
     *
     * Second, this folds the output in half to hide the data
     * fed back into the pool from the user and further mask
     * any patterns in the hash output.  (The exact folding
     * pattern is not important; the one used here is quick.)
     */
    for (i = 0; i < HASH_BUFFER_SIZE; i++) {
	UInt32 x = tmp[i], y = tmp[i + HASH_BUFFER_SIZE];
	Secrand_AddEntropyWords(x, y);
	buf[i] = x ^ y;
    }
}

/*
 * This function is exported.  It returns an UInt32 number with n bits
 * strong random bits, suitable for password generation etc.
 */
UInt32 Secrand_GetBits(int nbits)
{
    static UInt32 bitbucket[HASH_BUFFER_SIZE];
    static Int16  usedBits = 32 * HASH_BUFFER_SIZE;
    UInt32 *ptr;
    Int16  bitsAtPtr;
    UInt32 result = 0;

    /* ptr points to next position that has randomness left
     * bitsAtPtr tells how many low bits at ptr are random.
     */
    ptr       = bitbucket + (usedBits >> 5);
    bitsAtPtr = 32 - (usedBits & 31);

    for (;;) {
	if (usedBits == 32 * HASH_BUFFER_SIZE) {
	    /* We used up the whole pool, so refresh it.
	     */
	    Secrand_ExtractEntropy(bitbucket);
	    usedBits = 0;
	    ptr = bitbucket;
	    bitsAtPtr = 32;
	}

	if (nbits > bitsAtPtr) {
	    result = (result << bitsAtPtr) | *ptr;
	    usedBits += bitsAtPtr;
	    nbits -= bitsAtPtr;
	    *ptr++ = 0;
	    bitsAtPtr = 32;
	} else {
	    bitsAtPtr -= nbits;
	    result = (result << nbits) | (*ptr >> bitsAtPtr);
	    *ptr &= (1L << bitsAtPtr) - 1;
	    usedBits += nbits;
	    return result;
	}
    }
}
