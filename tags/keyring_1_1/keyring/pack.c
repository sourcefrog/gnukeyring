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

    
/* XXX: It seems there is some kind of bug here in resizing
 * the record, but I don't know what it is yet.
 *
 * From the Programmer's Companion: ``To resize a record to
 * grow or shrink its contents, call DmResizeRecord. This
 * routine automatically reallocates the record in another
 * heap of the same card if the current heap does not have
 * enough space for it. Note that if the data manager needs to
 * move the record into another heap to resize it, the handle
 * to the record changes. DmResizeRecord returns the new
 * handle to the record.''
 *
 * ``May display a fatal error message if any of the following
 * occur: [] You don t have write access to the database. []
 * The index parameter is out of range. [] The record chunk is
 * locked.''
 *
 * Alternatively I wonder if something really strange is happening
 * here, like perhaps we're running out of heap or dynamic memory.
 * Certainly the encryption stuff might be a bit
 * memory-intensive.
 *
 * TODO: Check record is released before resizing.
 *
 * TODO: Better error checking that e.g. we're not running past the
 * end of the record.  Display an error dialog rather than crashing.
 */

#include "includes.h"


static UInt32 packBodyLen, packRecLen;


/*
 * Calculate and store into packRecLen and packBodyLen the amount of
 * database space this key will use.
 */
static void Keys_CalcPackedSize(UnpackedKeyType const *unpacked)
{
    packBodyLen = unpacked->acctLen + 1
         + unpacked->passwdLen + 1
         + unpacked->notesLen + 1;

    if (packBodyLen & (kDESBlockSize-1))
	packBodyLen = (packBodyLen & ~(kDESBlockSize-1)) + kDESBlockSize;

    packRecLen = unpacked->nameLen + 1 + packBodyLen;
}


/*
 * Return a newly-allocated buffer containing a packed form of the
 * body of this key.  The caller should encrypt and store it, then
 * free the buffer.
 */
static char *Keys_PackBody(UnpackedKeyType const *u)
{
    char      *buf, *ptr;

    ptr = buf = MemPtrNew(packBodyLen);
    ErrFatalDisplayIf(!buf, "Not enough dynamic memory to encode record");

    Mem_CopyFromHandle(&ptr, u->acctHandle, u->acctLen+1);
    Mem_CopyFromHandle(&ptr, u->passwdHandle, u->passwdLen+1);
    Mem_CopyFromHandle(&ptr, u->notesHandle, u->notesLen+1);

    return buf;
}


/*
 * Encrypt and store an unpacked record into an open and locked
 * database record.
 */
static void Keys_WriteRecord(UnpackedKeyType const *unpacked, 
			     void *recPtr, UInt8 *cryptKey)
{
    UInt32     off = 0;
    void       *bodyBuf;

    DB_WriteStringFromHandle(recPtr, &off, unpacked->nameHandle,
                             unpacked->nameLen + 1); /* NUL */
    bodyBuf = Keys_PackBody(unpacked);
    DES3_Write(recPtr, off, bodyBuf, packBodyLen, cryptKey);
    MemPtrFree(bodyBuf);
}


/*
 * Write just a single NUL to keep space for this record.  It's not
 * marked dirty yet -- that'll happen when some real data is written
 * in.
 */
Err KeyDB_CreateNew(UInt16 *idx)
{
    MemHandle	recHandle;
    Char        *ptr;
    Err         err;

    *idx = dmMaxRecordIndex;
    recHandle = DmNewRecord(gKeyDB, idx, 1);
    if (!recHandle) 
        goto findErrOut;

    ptr = MemHandleLock(recHandle);
    if (!ptr)
        goto findErrOut;
    
    if ((err = DmWrite(ptr, 0, "", 1)))
        goto errOut;
    
    MemHandleUnlock(recHandle);
    
    return 0;
    
 findErrOut:
    err = DmGetLastErr();
 errOut:
    UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    return err;
}

void Key_SetCategory(UInt16 idx, UInt16 category)
{
     UInt16 attr;
     Err err;
     
     if ((err = DmRecordInfo(gKeyDB, idx, &attr, NULL, NULL)))
          goto fail;
     
     attr = (attr & ~dmRecAttrCategoryMask) | category;
     if ((err = DmSetRecordInfo(gKeyDB, idx, &attr, NULL)))
          goto fail;

     return;
     
 fail:
     UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
}


/*
 * Basic procedure to save a record:
 *
 * setup record:
 *   calculate the required record length
 *   resize record to the required length
 * lock record
 * write plaintext name
 * write body:
 *   allocate a temporary buffer equal to the encrypted-part length
 *   write the unencoded form into the temporary buffer
 *   allocate a temporary encryption buffer
 *   one block at a time, encrypt and write into the database
 *   release temporary buffer
 * unlock record
 * set record position
 */
void Keys_SaveRecord(UnpackedKeyType const *unpacked, UInt16 idx, 
		     UInt8 *recordKey)
{
    MemHandle recHandle;
    void	*recPtr;
    Err		err;

    Keys_CalcPackedSize(unpacked);
    ErrFatalDisplayIf(packRecLen > 8000,
		      __FUNCTION__ ": immoderate packRecLen"); /* paranoia */

    ErrNonFatalDisplayIf(idx == kNoRecord,
                         __FUNCTION__ ": no record to save");
    
    ErrFatalDisplayIf(idx > kMaxRecords, __FUNCTION__ ": outlandish idx");
    recHandle = DmResizeRecord(gKeyDB, idx, packRecLen);
    if (!recHandle) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, DmGetLastErr(),
                           __FUNCTION__);
	return;
    }
    recPtr = MemHandleLock(recHandle);
    Keys_WriteRecord(unpacked, recPtr, recordKey);
    MemHandleUnlock(recHandle);

    err = DmReleaseRecord(gKeyDB, idx, true);
    if (err)
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
}
