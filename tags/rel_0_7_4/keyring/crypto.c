/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999 Martin Pool
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

#include <Pilot.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "callback.h"

// ======================================================================
// DES3 functions

#undef DISABLE_DES

void DES3_Buf(VoidPtr from, VoidPtr to, ULong len, Boolean encrypt,
	      Byte const *key)
{
    Byte	other[kBlockSize];
    Err		err;
    
    ErrNonFatalDisplayIf(len & (kBlockSize-1),
			 __FUNCTION__ ": not block padded");
    ErrFatalDisplayIf(!to || !from, __FUNCTION__ ":null");

    do {
#ifndef DISABLE_DES	
	err = EncDES(from, (BytePtr) key, to, encrypt);
	if (err)
	    goto fail;

	err = EncDES(to, (BytePtr) key+kBlockSize, other, !encrypt);
	if (err)
	    goto fail;

	err = EncDES(other, (BytePtr) key, to, encrypt);
	if (err)
	    goto fail;
#else /* DISABLE_DES */
	MemMove(to, from, kBlockSize);
#endif /* DISABLE_DES */
	to += kBlockSize;
	from += kBlockSize;
	len -= kBlockSize;
    } while (len > 0);

    return;
    
 fail:
    App_ReportSysError(__FUNCTION__": EncDES", err);	
}


