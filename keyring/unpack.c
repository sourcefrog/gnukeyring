/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 *
 * $Id$
 * 
 * Tightly Bound -- store passwords securely on a handheld
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
#include "uiutil.h"


/* Convert from a packed database record into an unpacked in-memory
 * representation.  Return true if conversion was successful. */
void Keys_Unpack(MemHandle record, UnpackedKeyType *u)
{
    Int16       remain;
    Char *      ptr;
    Char *      plainBuf;
    Char *      cryptPtr;
    Err         err;

    ptr = MemHandleLock(record);    
    remain = MemHandleSize(record);
    
    u->nameHandle = Mem_ReadString(&ptr, &remain, &u->nameLen);

    plainBuf = MemPtrNew(remain);
    ErrFatalDisplayIf(!plainBuf, "Not enough memory to unpack record");

    cryptPtr = ptr;
    err = DES3_Read(cryptPtr, plainBuf, remain);
    if (err) {
        /* TODO: If this failed, indicate to the caller that we couldn't unpack the record. */
        UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);
    }

    ptr = plainBuf;
    u->acctHandle = Mem_ReadString(&ptr, &remain, &u->acctLen);
    u->passwdHandle = Mem_ReadString(&ptr, &remain, &u->passwdLen);
    u->notesHandle = Mem_ReadString(&ptr, &remain, &u->notesLen);

    MemPtrFree(plainBuf); 

    MemHandleUnlock(record);
}


