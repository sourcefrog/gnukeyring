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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef _PRONOUNCE_H_
#define _PRONOUNCE_H_

#define RULE_SIZE             34

#define NOT_BEGIN_SYLLABLE    010
#define NO_FINAL_SPLIT        04
#define VOWEL                 02
#define ALTERNATE_VOWEL       01
#define NO_SPECIAL_RULE       0

#define BEGIN                 0200  /* digram should begin a new syllable */
#define NOT_BEGIN             0100  /* digram must not start a syllable */
#define BREAK                 040   /* digram should be splitted into two syllables */
#define PREFIX                020   /* digram requires a vocal in front */
#define ILLEGAL_PAIR          010   /* digram must not occur */
#define SUFFIX                0     /* Not needed any more. */
#define END                   02    /* digram should end a syllable */
#define NOT_END               01    /* digram must not end a syllable */
#define ANY_COMBINATION       0

struct unit
{
  Char unit_code[3];
  UInt8 flags;
};

#define MAX_PWLEN             20

typedef struct {
  UInt16 unit_length;
  UInt16 saved_units;
  UInt8  units[MAX_PWLEN + 2];
} PronStateType;


#endif /* _PRONOUNCE_H_ */
