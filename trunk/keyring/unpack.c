/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; indent-tabs-mode: t; -*-
 *
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

#include "keyring.h"
#include "record.h"
#include "unpack.h"
#include "memutil.h"
#include "resource.h"
#include "auto.h"
#include "crypto.h"


/* Convert from a packed database record into an unpacked in-memory
 * representation.  Return true if conversion was successful. */
void Keys_Unpack(MemHandle record, UnpackedKeyType *u,
		 UInt8 const *UNUSED(key))
{
    Char *	recPtr;
    UInt32	recLen;
    Int32	nameLen;

#if 0
    Char *	plainBuf;
    Char *	cryptPtr;
    Char *	ptr;
    Err		err;
#endif 

    recPtr = MemHandleLock(record);    
    recLen = MemHandleSize(record);
    
    u->nameHandle = Mem_StrToHandle(recPtr, &nameLen);
    u->nameLen = nameLen;

#if 0
    plainBuf = MemPtrNew(recLen);
    ErrFatalDisplayIf(!plainBuf, "Not enough memory to unpack record");

    cryptPtr = recPtr + nameLen + 1;
    err = DES3_Buf(cryptPtr, plainBuf, recLen - (cryptPtr - recPtr), false,
		   key);
    if (err) {
	/* TODO: If this failed, indicate to the caller that we couldn't unpack the record. */
	App_ReportSysError(CryptoErrorAlert, err);
    }

    ptr = plainBuf;

    u->acctHandle = Mem_ReadString(&ptr, &u->acctLen);
    u->passwdHandle = Mem_ReadString(&ptr, &u->passwdLen);
    u->notesHandle = Mem_ReadString(&ptr, &u->notesLen);
    Mem_ReadChunk(&ptr, sizeof(DateType), &u->lastChange);
    MemPtrFree(plainBuf);

#endif 0
    u->lastChangeDirty = false;

    MemHandleUnlock(record);
}


