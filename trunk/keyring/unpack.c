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


/* Convert from a packed database record into an unpacked in-memory
 * representation.  Return true if conversion was successful. */
void Keys_UnpackRecord(Char *recPtr, UnpackedKeyType *u, UInt8 *recordKey)
{
    Int16       remain;
    Char *      plainBuf;
    Char *      cryptPtr;
    Err         err;

    MemSet(u, sizeof(UnpackedKeyType), (UInt8) 0);
    
    remain = MemPtrSize(recPtr);
    u->nameHandle = Mem_ReadString(&recPtr, &remain, &u->nameLen);

    if (remain < 0) {
        FrmCustomAlert(ID_KeyDatabaseAlert,
                       "record underflow", __FUNCTION__, "");
	return;
    }

    plainBuf = MemPtrNew(remain);
    if (!plainBuf)  {
         FrmCustomAlert(ID_KeyDatabaseAlert,
                        "not enough memory to unpack record",
                        __FUNCTION__, "");
         return;
    }

    cryptPtr = recPtr;
    err = DES3_Read(cryptPtr, plainBuf, remain, recordKey);
    if (err) {
        /* TODO: If this failed, indicate to the caller that we
         * couldn't unpack the record. */
        UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);
    }

    recPtr = plainBuf;
    u->acctHandle = Mem_ReadString(&recPtr, &remain, &u->acctLen);
    u->passwdHandle = Mem_ReadString(&recPtr, &remain, &u->passwdLen);
    u->notesHandle = Mem_ReadString(&recPtr, &remain, &u->notesLen);
    Mem_ReadChunk(&recPtr, &remain, &u->lastChange, sizeof(DateType));
	    
    if (remain < 0) {
        FrmCustomAlert(ID_KeyDatabaseAlert,
                       "record underflow", __FUNCTION__, "");
    }

    MemPtrFree(plainBuf); 
}
