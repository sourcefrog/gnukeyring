/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

#include "includes.h"

// ======================================================================
// DES3 functions


#ifndef DISABLE_DES

void CryptoPrepareKey(UInt8 *rawKey, CryptoKey cryptKey)
{
    des_set_odd_parity((des_cblock*) rawKey);
    des_set_key((des_cblock*) rawKey, cryptKey[0]);
    des_set_odd_parity((des_cblock*) rawKey + 1);
    des_set_key((des_cblock*) rawKey + 1, cryptKey[1]);
}

Err CryptoRead(void * from, void * to, UInt32 len, CryptoKey cryptKey)
{
    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");
    while (len >= kDESBlockSize) {
	des_ecb2_encrypt(from, to, cryptKey[0], cryptKey[1], false);

	to += kDESBlockSize;
	from += kDESBlockSize;
	len -= kDESBlockSize;
    } 

    return 0;
}


Err CryptoWrite(void *recPtr, UInt32 off, char const *from, UInt32 len,
		CryptoKey cryptKey)
{
    des_cblock third;
    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");
    while (len >= kDESBlockSize) {
	des_ecb2_encrypt((des_cblock*)from, &third, 
			 cryptKey[0], cryptKey[1], true);

        DmWrite(recPtr, off, third, kDESBlockSize);

        off += kDESBlockSize;
	from += kDESBlockSize;
	len -= kDESBlockSize;
    }

    return 0;
}

#else /* DISABLE_DES */

void CryptoPrepareKey(UInt8 *UNUSED(rawKey), CryptoKey UNUSED(cryptKey))
{
}

/*
 * Encrypt (or not!) and write out
 */
Err CryptoWrite(void *recPtr, UInt32 off,
		char const *src, UInt32 len,
		CryptoKey UNUSED(key))
{
    return DmWrite(recPtr, off, src, len);
}


Err CryptoRead(void * from, void * to, UInt32 len, CryptoKey UNUSED(key))
{
    MemMove(to, from, len);

    return 0;
}
#endif /* DISABLE_DES */

