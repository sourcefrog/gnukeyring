/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
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

// ======================================================================
// DES3 functions

/*
 * Encrypt (or not!) and write out
 */
void DES3_Write(void *recPtr, UInt32 off,
                char const *src, UInt32 len)
{
    DmWrite(recPtr, off, src, len);
}



#define DISABLE_DES

#ifndef DISABLE_DES
Err DES3_Buf(void * from, void * to, UInt32 len, Boolean encrypt,
	     UInt8 const *key)
{
    UInt8	other[kDESBlockSize];
    Err		err = 0;

    ErrNonFatalDisplayIf(len & (kDESBlockSize-1),
			 __FUNCTION__ ": not block padded");

    do {
	err = EncDES(from, (UInt8 *) key, to, encrypt);
	if (err)
	    return err;

	err = EncDES(to, (UInt8 *) key+kDESBlockSize, other, !encrypt);
	if (err)
	    return err;

	err = EncDES(other, (UInt8 *) key, to, encrypt);
	if (err)
	    return err;

	to += kDESBlockSize;
	from += kDESBlockSize;
	len -= kDESBlockSize;
    } while (len > 0);

    return 0;
}

#else /* DISABLE_DES */

Err DES3_Buf(void * from, void * to, UInt32 len, Boolean UNUSED(encrypt),
	     UInt8 const UNUSED(*key))
{
    MemMove(to, from, len);

    return 0;
}
#endif /* DISABLE_DES */
