/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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


Err DES3_Read(void * from, void * to, UInt32 len, UInt8 *cryptKey)
{
    des_key_schedule ks1, ks2;

    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");
    des_set_key((char*)cryptKey, ks1);
    des_set_key((char*)cryptKey + DES_KEY_SZ, ks2);

    do {
	des_ecb2_encrypt(from, to, ks1, ks2, false);

	to += kDESBlockSize;
	from += kDESBlockSize;
	len -= kDESBlockSize;
    } while (len > 0);

    return 0;
}


Err DES3_Write(void *recPtr, UInt32 off, char const *from, UInt32 len,
               UInt8 *cryptKey)
{
    UInt8	third[kDESBlockSize];
    des_key_schedule ks1, ks2;

    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");
    des_set_key(cryptKey, ks1);
    des_set_key(cryptKey + DES_KEY_SZ, ks2);

    do {
	des_ecb2_encrypt(from, third, ks1, ks2, true);

        DmWrite(recPtr, off, third, kDESBlockSize);

        off += kDESBlockSize;
	from += kDESBlockSize;
	len -= kDESBlockSize;
    } while (len > 0);

    return 0;
}


#else /* DISABLE_DES */

/*
 * Encrypt (or not!) and write out
 */
 Err DES3_Write(void *recPtr, UInt32 off,
               char const *src, UInt32 len,
               UInt8 *UNUSED(key))
{
    return DmWrite(recPtr, off, src, len);
}


 Err DES3_Read(void * from, void * to, UInt32 len)
{
    MemMove(to, from, len);

    return 0;
}
#endif /* DISABLE_DES */
