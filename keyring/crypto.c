/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@humbug.org.au>
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

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "crypto.h"
#include "snib.h"

// ======================================================================
// DES3 functions


#ifndef DISABLE_DES

/*
 * Decrypt or encrypt a block using the session key, which must already be
 * unlocked.
 */
static Err DES3_Block(void const *from, void *to, Boolean encrypt,
                      UInt8 *cryptKey)
{
    Err err;
    char other[kDESBlockSize];
    UInt8 *kp;

    kp = cryptKey;
    ErrFatalDisplayIf(!kp, "record key unready");
    err = EncDES((UInt8 *) from, kp, to, encrypt);
    if (err)
        return err;

    kp = cryptKey + kDESKeySize;
    err = EncDES((UInt8 *) to, kp, other, !encrypt);
    if (err)
        return err;
    
    kp = cryptKey;
    err = EncDES((UInt8 *) other, kp, to, encrypt);
    if (err)
        return err;

    return 0;
}


Err DES3_Read(void * from, void * to, UInt32 len)
{
    //    Err		err = 0;

    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");

    do {
        DES3_Block(from, to, false, g_Snib->recordKey);

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
    Err		err = 0;

    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");

    do {
        err = DES3_Block(from, third, true, cryptKey);

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
