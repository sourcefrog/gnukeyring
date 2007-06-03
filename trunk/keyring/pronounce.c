/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2002-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

/*
                                                 
The following is a listing of the source code referenced in the
Appendix A of the Automated Password Generator Standard, extracted
from http://www.eff.org/Privacy/Newin/New_nist/fips181.txt on 8 May
2002.  There is no licensing information regarding this code in the
above document, however, it seems clear that it is intended to be used
as a reference implementation.  Derivative works would therefore be
OK.

The idea and first implementation to use this code in keyring is due
to Robin Stephenson.

*/

#include "includes.h"

#define IS_FLAG(flag)         (digram[last_unit]][unit] & (flag))
#define MAX_UNACCEPTABLE      20
#define MAX_RETRIES           (4 * pwlen + RULE_SIZE)


/*
 * This is the standard random unit generating routine for
 * get_syllable().  It does not reference the digrams, but assumes
 * that it contains 34 units in a particular order.  This routine
 * attempts to return unit indexes with a distribution approaching
 * that of the distribution of the 34 units in English.  In order to
 * do this, a random number (supposedly uniformly distributed) is used
 * to do a table lookup into an array containing unit indices.  There
 * are 211 entries in the array for the random_unit entry point.  The
 * probability of a particular unit being generated is equal to the
 * fraction of those 211 entries that contain that unit index.  For
 * example, the letter `a' is unit number 1.  Since unit index 1
 * appears 10 times in the array, the probability of selecting an `a'
 * is 10/211.
 *
 * Changes may be made to the digram table without affect to this
 * procedure providing the letter-to-number correspondence of the
 * units does not change.  Likewise, the distribution of the 34 units
 * may be altered (and the array size may be changed) in this
 * procedure without affecting the digram table or any other programs
 * using the random_word subroutine.
 *
 * FIXME:  Do we really want this?  Passwords would be much safer if
 * the characters are more equally distributed, but they may be harder
 * to remember.
 */
static const UInt8 numbers[] = {
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 1, 1, 1, 1,
  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
  5, 5, 5, 5, 5, 5, 5, 5,
  6, 6, 6, 6, 6, 6, 6, 6,
  7, 7, 7, 7, 7, 7,
  8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
  9, 9, 9, 9, 9, 9, 9, 9,
  10, 10, 10, 10, 10, 10, 10, 10,
  11, 11, 11, 11, 11, 11,
  12, 12, 12, 12, 12, 12,
  13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
  14, 14, 14, 14, 14, 14, 14, 14, 14, 14,
  15, 15, 15, 15, 15, 15,
  16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
  17, 17, 17, 17, 17, 17, 17, 17,
  18, 18, 18, 18, 18, 18, 18, 18, 18, 18,
  19, 19, 19, 19, 19, 19,
  20, 20, 20, 20, 20, 20, 20, 20,
  21, 21, 21, 21, 21, 21, 21, 21,
  22,
  23, 23, 23, 23, 23, 23, 23, 23,
  24,
  25,
  26,
  27,
  28,
  29, 29,
  30,
  31,
  32,
  33
};


/*
 * This structure has a typical English frequency of vowels.  The
 * value of an entry is the vowel position (a=0, e=4, i=8, o=14, u=19,
 * y=23) in the rules array.  The number of times the value appears is
 * the frequency.  Thus, the letter "a" is assumed to appear 2/12 =
 * 1/6 of the time.  This array may be altered if better data is
 * obtained.  The routines that use vowel_numbers will adjust to the
 * size difference automatically.
 */
static const UInt8 vowel_numbers[] = {
  0, 0, 4, 4, 4, 8, 8, 14, 14, 19, 19, 23
};

/*
 * Select a unit (a letter or a consonant group).  If a vowel is
 * expected, use the vowel_numbers array rather than looping through
 * the numbers array until a vowel is found.
 */
static UInt16 random_unit (register UInt16 type)
{
    register UInt8 rand;
    
    /* 
     * Sometimes, we are asked to explicitly get a vowel (i.e., if a
     * digram pair expects one following it).  This is a shortcut to do
     * that and avoid looping with rejected consonants.
     */
    if (type & VOWEL)
    {
	while ((rand = Secrand_GetByte()) > 12*21) 
	{
	    /* regenerate random. */
	}
	return vowel_numbers[rand % 12];
    }
    else
    {
	while ((rand = Secrand_GetByte()) > 
	       sizeof (numbers) / sizeof (UInt16)) 
	{
	    /* regenerate random. */
	}
	/* 
	 * Get any letter according to the English distribution.
	 */
	return numbers[rand];
    }
}

/*
 * Generate next unit to password, making sure that it follows
 * these rules:
 *   1. Each syllable must contain exactly 1 or 2 consecutive
 *      vowels, where y is considered a vowel.
 *   2. Syllable end is determined as follows:
 *        a. Vowel is generated and previous unit is a
 *           consonant and syllable already has a vowel.  In
 *           this case, new syllable is started and already
 *           contains a vowel.
 *        b. A pair determined to be a "break" pair is encountered.
 *           In this case new syllable is started with second unit
 *           of this pair.
 *        c. End of password is encountered.
 *        d. "begin" pair is encountered legally.  New syllable is
 *           started with this pair.
 *        e. "end" pair is legally encountered.  New syllable has
 *           nothing yet.
 *   3. Try generating another unit if:
 *        a. third consecutive vowel and not y.
 *        b. "break" pair generated but no vowel yet in current
 *           or previous 2 units are "not_end".
 *        c. "begin" pair generated but no vowel in syllable
 *           preceding begin pair, or both previous 2 pairs are
 *          designated "not_end".
 *        d. "end" pair generated but no vowel in current syllable
 *           or in "end" pair.
 *        e. "not_begin" pair generated but new syllable must
 *           begin (because previous syllable ended as defined in
 *           2 above).
 *        f. vowel is generated and 2a is satisfied, but no syllable
 *           break is possible in previous 3 pairs.
 *        g. Second and third units of syllable must begin, and
 *           first unit is "alternate_vowel".
 */
void Pron_GetSyllable (Char *syllable, UInt16 pwlen, 
		       PronStateType *state, void *prondata)
{
    Int16  syll_length;
    UInt16 vowel_count, unit_ptr;
    UInt16 next_vowel;
    UInt16 tries;
    Int16  last_unit, unit;
    Int8   last_flags, flags;
    Int16  length_left;
    Int16  new_length_left;
    UInt16 saved_unit;

    struct unit (*rules);
    UInt8 (*digram)[RULE_SIZE];

    rules  = prondata;
    digram = prondata + RULE_SIZE * sizeof(struct unit);

    /* 
     * Try for a new syllable.  Initialize all pertinent syllable
     * variables.
     */

 retry_syllable:
    tries = 0;
    vowel_count = 0;
    length_left = pwlen;
    next_vowel = NO_SPECIAL_RULE;
    syll_length = state->saved_units;
    unit_ptr = state->unit_length + syll_length;
    last_flags = flags = 0;
    saved_unit = 0;
    syllable[0] = 0;
    
    if (unit_ptr == 0)
	last_unit = -1;
    else
	last_unit = state->units[unit_ptr - 1];

    /* 
     * If there are saved_unit's from the previous syllable,
     * we have to update flags.
     */
    if (syll_length > 0) {
	if ((rules[last_unit].flags & VOWEL) &&
	    !(rules[last_unit].flags & ALTERNATE_VOWEL))
	    vowel_count++;
			     
	length_left -= StrLen(rules[last_unit].unit_code);
	if (syll_length > 1) {
	    UInt8 llunit = state->units[unit_ptr-2];
	    if ((rules[llunit].flags & VOWEL))
		vowel_count++;
	    length_left -= StrLen(rules[llunit].unit_code);
	    last_flags = digram[llunit][last_unit];       
	}
    }


    /*
     * This loop finds all the units for the syllable.
     */
    while (length_left > 0)
    {
	/*
	 * This label is jumped to until a valid unit is found for the
	 * current position within the syllable.
	 */
    retry_unit:

	if (tries++ > MAX_RETRIES)
	    goto retry_syllable;
	
	/* 
	 * If we don't have to scoff the saved units, we
	 * generate a random one.  If we know it has to be a
	 * vowel, we get one rather than looping through until
	 * one shows up.
	 */

	if (/* We have only one letter left and need a vowel */
	    (length_left == 1 && vowel_count == 0)
	    /* We have two consonants, next must be vowel */
	    || (unit_ptr >= 2
		&& !((rules[state->units[unit_ptr-2]].flags
		      | rules[last_unit].flags) & VOWEL)))
	    next_vowel = VOWEL;
	else
	    next_vowel = NO_SPECIAL_RULE;

	unit = random_unit (next_vowel);
	new_length_left = length_left - (Int16) StrLen (rules[unit].unit_code);
	
	/*
	 * Prevent having a word longer than expected.
	 */
	if (new_length_left < 0)
	    goto retry_unit;
	
	/* Always check for illegal pairs, triple vocals and triple
         * consonants 
	 */
	if (unit_ptr > 0 && (digram[last_unit][unit] & ILLEGAL_PAIR))
	    goto retry_unit;

	if (unit_ptr >= 2) {
	    if ((rules[unit].flags & VOWEL)
		&& (rules[last_unit].flags & VOWEL)
		&& (rules[state->units[unit_ptr-2]].flags
		    & (VOWEL | ALTERNATE_VOWEL)) == VOWEL)
		goto retry_unit;
	}
	
	/* Reject syllables ending with a single e and containing no
	 * other syllables
	 */
	if (new_length_left == 0
	    && vowel_count == 0
	    && (rules[unit].flags & NO_FINAL_SPLIT))
	    goto retry_unit;
	
	/*
	 * First unit of syllable.  This is special because the
	 * digram tests require 2 units and we don't have that
	 * yet.  Nevertheless, we can perform some checks.
	 */
	if (syll_length == 0)
	{
	    /* 
	     * If the shouldn't begin a syllable, don't use it.
	     */
	    if (rules[unit].flags & NOT_BEGIN_SYLLABLE)
		goto retry_unit;
	}
	else
	{
	    /* 
	     * There are some digram tests that are universally
	     * true.  We test them out.
	     */
	    flags = digram[last_unit][unit];
	    
	    /*
	     * Reject units that will be split between
	     * syllables when the syllable has no vowels in
	     * it.
	     */
	    if ((flags & BREAK) && (vowel_count == 0))
		goto retry_unit;

	    /*
	     * Reject a unit that will end a syllable when
	     * no previous unit was a vowel and neither is
	     * this one.
	     */
	    if ((flags & END) && (vowel_count == 0) && 
		!(rules[unit].flags & VOWEL))
		goto retry_unit;
	    
	    /*
	     * If this is the last unit of a word, we
	     * should reject any digram that cannot end
	     * a syllable.
	     */
	    if (new_length_left == 0 && (flags & NOT_END))
		goto retry_unit;
	    
	    if (syll_length == 1)
	    {
		/*
		 * Reject the unit if we are at the starting
		 * digram of a syllable and it does not fit.
		 */
		if ((flags & NOT_BEGIN))
		    goto retry_unit;
	    }
	    else
	    {
		/*
		 * Do not allow syllables where the first letter
		 * is y and the next pair can begin a syllable.
		 * This may lead to splits where y is left alone
		 * in a syllable.  Also, the combination does
		 * not sound to good even if not split.
		 */
		if (((syll_length == 2) &&
		     ((flags & BEGIN)) &&
		     (rules[state->units[0]].flags & ALTERNATE_VOWEL)))
		    goto retry_unit;

		/*
		 * Reject the unit if the digram it forms
		 * wants to break the syllable, but the
		 * resulting digram that would end the
		 * syllable is not allowed to end a
		 * syllable.
		 */
		if ((flags & BREAK) && (last_flags & NOT_END))
		    goto retry_unit;

		/*
		 * Reject the unit if the digram it forms
		 * expects a vowel preceding it and there is
		 * none.
		 */
		if ((flags & PREFIX) &&
		    !(rules[state->units
			   [unit_ptr - 2]].flags & VOWEL))
		    goto retry_unit;
		
		/*
		 * The following checks occur when the current
		 * unit is a vowel and we are not looking at a
		 * word ending with an e.
		 */
		if ((vowel_count != 0) &&
		    (rules[unit].flags & VOWEL) &&
		    !(rules[last_unit].flags & VOWEL))
		{
		    /*
		     * Check for the case of
		     * vowels-consonants-vowel, which is only
		     * legal if the last vowel is an e and we
		     * are the end of the word (wich is not
		     * happening here due to a previous check.
		     */
		    if (new_length_left > 0 ||
			!(rules[last_unit].flags & NO_FINAL_SPLIT))
		    {
			/*
			 * Try to save the vowel for the next
			 * syllable, but if the syllable left
			 * here is not proper (i.e. the
			 * resulting last digram cannot
			 * legally end it), just discard it
			 * and try for another.
			 */
			if ((last_flags & NOT_END))
			    goto retry_unit;

			saved_unit = 1;
			state->units[unit_ptr] = unit;
			break;
		    }
		}
	    }
    		    
	    /*
	     * The unit picked and the digram formed are legal.
	     * We now determine if we can end the syllable.  It
	     * may, in some cases, mean the last unit(s) may be
	     * deferred to the next syllable.  We also check
	     * here to see if the digram formed expects a vowel
	     * to follow.
	     */
    
	    /*
	     * Since we have a vowel in the syllable
	     * already, if the digram calls for the end of
	     * the syllable, we can legally split it
	     * off. We also make sure that we are not at
	     * the end of the dangerous because that
	     * syllable may not have vowels, or it may not
	     * be a legal syllable end, and the retrying
	     * mechanism will loop infinitely with the
	     * same digram.
	     */
	    if ((vowel_count != 0) && (new_length_left > 0))
	    {
		/*
		 * If we must begin a syllable, we do so if
		 * the only vowel in THIS syllable is not
		 * part of the digram we are pushing to the
		 * next syllable.
		 */
		if ((flags & BEGIN) &&
		    (syll_length > 1) &&
		    !((vowel_count == 1) &&
		      (rules[last_unit].flags & VOWEL)))
		{
		    saved_unit = 2;
		    state->units[unit_ptr] = unit;

		    /* remove last_unit from current syllable. */
		    syll_length--;
		    unit_ptr--;
		    break;
		}
		else if ((flags & BREAK))
		{
		    saved_unit = 1;
		    state->units[unit_ptr] = unit;
		    break;
		}
	    }
	}
	
	/* 
	 * If the unit is a vowel, count it in.  However, if
	 * the unit is a y and appears at the start of the
	 * syllable, treat it like a consonant (so that words
	 * like year can appear and not conflict with the 3
	 * consecutive vowel rule.
	 */
	if ((rules[unit].flags & VOWEL) &&
	    ((syll_length > 0) ||
	     !(rules[unit].flags & ALTERNATE_VOWEL)))
	    vowel_count++;
	
	/*
	 * Append the unit to the syllable and update length_left,
	 * syll_length and last_unit.
	 */
	state->units[unit_ptr] = unit;
	syll_length++;
	unit_ptr++;
	length_left = new_length_left;
	last_unit = unit;
	last_flags = flags;

	if ((flags & END))
	    break;
    }

    /* Create the textual form of the syllable */
    while (state->unit_length < unit_ptr)
	StrCat(syllable, rules[state->units[state->unit_length++]].unit_code);

    state->unit_length = unit_ptr;
    state->saved_units = saved_unit;
    return;
}


/*
 * local variables:
 * mode: c
 * c-basic-offset: 4
 * eval: (c-set-offset 'substatement-open 0)
 * end:
 */
