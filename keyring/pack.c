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
 */

#include <PalmOS.h>

#include "keyring.h"
#include "record.h"
#include "pack.h"
#include "crypto.h"
#include "auto.h"
#include "resource.h"


/*
 * Calculate the size a record will occupy when it is packed. 
 *
 * All the fields except for the name are encrypted into DES 8-byte
 * blocks, so we have to round up to the next full block size. */
static UInt32 Keys_CalcPackedLength(UnpackedKeyType const *unpacked)
{
    UInt32 plainSize = unpacked->nameLen + 1;
    UInt32 encSize = unpacked->acctLen + 1
	+ unpacked->passwdLen + 1
	+ unpacked->notesLen + 1
	+ sizeof(UInt32);		/* date */

    if (encSize & (kDESBlockSize-1))
	encSize = (encSize & ~(kDESBlockSize-1)) + kDESBlockSize;

    return encSize + plainSize;
}


#if 0

/* Convert from an unpacked in-memory representation into the packed
 * form written into the database. */
void * KeyRecord_Pack(UnpackedKeyType const *u,
                      UInt8 const *key)
{
    int		dateLen;
    Char *	ptr; // Moves through buffer filling with data
    Char *     startCrypt;     // Start of data that should be enc.
    Char *     buf; // Start of buffer
    UInt32	recLen;
    Err		err;
    
    recLen = KeyRecord_CalcPackedLength(u);
    buf = MemPtrNew(recLen);
    ErrFatalDisplayIf(!buf, "Not enough dynamic memory to encode record");
    ptr = buf;

    Mem_CopyFromHandle(&ptr, u->nameHandle, u->nameLen+1);
    startCrypt = ptr;

    Mem_CopyFromHandle(&ptr, u->acctHandle, u->acctLen+1);
    Mem_CopyFromHandle(&ptr, u->passwdHandle, u->passwdLen+1);
    Mem_CopyFromHandle(&ptr, u->notesHandle, u->notesLen+1);

    dateLen = sizeof(DateType);
    MemMove(ptr, (void *) &u->lastChange, dateLen);
    ptr += dateLen;

    /* Can we really encrypt in place like this?  It looks dodgy to me.  Perhaps
     * we'd better instead */
    if ((err = DES3_Buf(startCrypt, startCrypt, recLen - (startCrypt-buf), true,
			key))) {
	/* TODO: If this failed, indicate to the caller that we
	 * couldn't pack the record. */
	App_ReportSysError(CryptoErrorAlert, err);
    }
	    
    return buf;
}
#endif

static void Keys_WriteRecord(UnpackedKeyType const *unpacked, void *recPtr)
{
    Char *fldPtr;

    fldPtr = MemHandleLock(unpacked->nameHandle);
    DmStrCopy(recPtr, 0, fldPtr);
    MemHandleUnlock(unpacked->nameHandle);
}


static MemHandle Keys_PrepareNew(UInt16 *idx, Int16 recLen)
{
    MemHandle	recHandle;

    *idx = dmMaxRecordIndex;
    recHandle = DmNewRecord(gKeyDB, idx, recLen);
    if (!recHandle) {
	App_ReportSysError(KeyDatabaseAlert, DmGetLastErr());
	return NULL;
    }

    return recHandle;
}


static MemHandle Keys_PrepareExisting(UInt16 *idx, Int16 recLen)
{
    MemHandle	recHandle;

    recHandle = DmResizeRecord(gKeyDB, *idx, recLen);
    if (!recHandle) {
	App_ReportSysError(KeyDatabaseAlert, DmGetLastErr());
	return NULL;
    }

    return recHandle;
}


/*
 * Basic procedure to save a record:
 *
 * setup record:
 *   calculate the required record length
 *   if there is an existing record:
 *     resize it to the required length
 *   else:
 *     allocate a new record of the required length
 * lock record
 * write plaintext name
 * write body:
 *   allocate a temporary buffer equal to the encrypted-part length
 *   write the unencoded form into the temporary buffer
 *   allocate a temporary encryption buffer
 *   one block at a time, encrypt and write into the database
 *   release temporary buffer
 * unlock record
 * set record category
 * set record position
 */
void Keys_SaveRecord(UnpackedKeyType const *unpacked, UInt16 *idx)
{
    MemHandle recHandle;
    void	*recPtr;
    Err		err;
    Int16	recLen;

    recLen = Keys_CalcPackedLength(unpacked);
    ErrFatalDisplayIf(recLen < 0 || recLen > 8000,
		      __FUNCTION__ ": immmoderate recLen"); /* paranoia */

    if (*idx == kNoRecord) {
	recHandle = Keys_PrepareNew(idx, recLen);
    } else {
	ErrFatalDisplayIf(*idx > kMaxRecords, __FUNCTION__ ": outlandish idx");
	recHandle = Keys_PrepareExisting(idx, recLen);
    }

    if (!recHandle)
	return;

    ErrFatalDisplayIf(*idx > kMaxRecords, __FUNCTION__ ": outlandish idx");
    
    recPtr = MemHandleLock(recHandle);
    Keys_WriteRecord(unpacked, recPtr);
    MemHandleUnlock(recHandle);

    err = DmReleaseRecord(gKeyDB, *idx, true);
    if (err)
	App_ReportSysError(KeyDatabaseAlert, err);
}

