/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 *
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool
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

/* TODO: Check that the terminating NULs in the strings are accounted
 * for correctly. */

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "memutil.h"
#include "record.h"
#include "keydb.h"
#include "crypto.h"
#include "passwd.h"
#include "resource.h"

static Int16 KeyDB_CompareRecords(void * rec1, void * rec2, Int16 other,
			 SortRecordInfoPtr info1,
			 SortRecordInfoPtr info2,
			 MemHandle appInfoHand);

// ======================================================================
// Key record manipulation


/* Compare records for sorting or sorted insertion.
 *
 * Because all records begin with the strz record name the comparison
 * is pretty simple: we sort in string order, except that deleted
 * records go to the end.  */
static Int16 KeyDB_CompareRecords(void * rec1, void * rec2,
				  Int16 UNUSED(other),
				  SortRecordInfoPtr info1,
				  SortRecordInfoPtr info2,
				  MemHandle UNUSED(appInfoHand))
{
    Int16 result;
    Char	*cp1, *cp2;

    if (info1 && (info1->attributes & dmRecAttrDelete))
	result = +1;
    else if (info2 && (info2->attributes & dmRecAttrDelete))
	result = -1;
    else {
	cp1 = (Char *) rec1;
	cp2 = (Char *) rec2;
	
	if (rec1  &&  !rec2)
	    result = -1;
	else if (!rec1  &&  rec2)
	    result = +1;
	else if (!rec1 && !rec2)
	    result = 0;
	else if (*cp1 && !*cp2)
	    result = -1;
	else if (!*cp1 && *cp2)
	    result = +1;
	else 
	    result = StrCompare(cp1, cp2);
    }
    return result;
}



void KeyRecord_Reposition(Char * name, UInt16 *idx, UInt16 *position)
{
    UInt16 	attr;
    UInt32 	uniqueID;
    MemHandle	moveHandle;
    Err 	err;
    
    DmRecordInfo(gKeyDB, *idx, &attr, &uniqueID, NULL);
    err = DmDetachRecord(gKeyDB, *idx, &moveHandle);
    if (err) {
	App_ReportSysError(KeyDatabaseAlert, err);
	return;
    }
	
    *idx = DmFindSortPosition(gKeyDB, (void *) name, 0,
			      KeyDB_CompareRecords, 0);

    err = DmAttachRecord(gKeyDB, idx, moveHandle, 0);
    if (err) {
	App_ReportSysError(KeyDatabaseAlert, err);
	return;
    }
    DmSetRecordInfo(gKeyDB, *idx, &attr, &uniqueID);

    *position = DmPositionInCategory(gKeyDB, *idx, gPrefs.category);
}


/* Calculate the size a record will occupy when it is packed. */
static UInt32 KeyRecord_CalcPackedLength(UnpackedKeyType const *unpacked)
{
    UInt32 plainSize = unpacked->nameLen + 1;
    UInt32 encSize = unpacked->acctLen + 1
	+ unpacked->passwdLen + 1
	+ unpacked->notesLen + 1
	+ sizeof(UInt32);		/* date */

    /* All the fields except for the name are encrypted into DES
     * 8-byte blocks, so we have to round up to the next full block
     * size. */
    if (encSize & (kBlockSize-1))
	encSize = (encSize & ~(kBlockSize-1)) + kBlockSize;

    return encSize + plainSize;
}


#ifdef REALLY_OBLITERATE
/* Scribble over all text in memory referenced by the unpacked
 * structure, so that unencrypted information is not left in
 * memory. */
void UnpackedKey_Obliterate(UnpackedKeyPtr u) {
    Mem_ObliterateHandle(u->nameHandle);
    Mem_ObliterateHandle(u->acctHandle);
    Mem_ObliterateHandle(u->passwdHandle);
    Mem_ObliterateHandle(u->notesHandle);
    u->lastChange.year = 0;
    u->lastChange.month = 0;
    u->lastChange.day = 0;
}
#endif /* REALLY_OBLITERATE */


void UnpackedKey_Free(UnpackedKeyPtr u) {
    if (u->nameHandle)
	MemHandleFree(u->nameHandle);
    if (u->acctHandle)
	MemHandleFree(u->acctHandle);
    if (u->passwdHandle)
	MemHandleFree(u->passwdHandle);
    if (u->notesHandle)
	MemHandleFree(u->notesHandle);

    u->nameHandle = u->acctHandle = u->passwdHandle = u->notesHandle
	= NULL;
}


/* Convert from a packed database record into an unpacked in-memory
 * representation.  Return true if conversion was successful. */
void KeyRecord_Unpack(MemHandle record, UnpackedKeyType *u,
		      UInt8 const *key)
{
    Char *	recPtr;
    Char *	plainBuf;
    Char *	cryptPtr;
    UInt32	recLen;
    Char *	ptr;
    Int32	nameLen;
    Err		err;

    recPtr = MemHandleLock(record);
    
    recLen = MemHandleSize(record);
    plainBuf = MemPtrNew(recLen);
    ErrFatalDisplayIf(!plainBuf, "Not enough memory to unpack record");
    
    u->nameHandle = Mem_StrToHandle(recPtr, &nameLen);
    u->nameLen = nameLen;

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
    u->lastChangeDirty = false;

    MemPtrFree(plainBuf);
    MemHandleUnlock(record);
}


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

    if ((err = DES3_Buf(startCrypt, startCrypt, recLen - (startCrypt-buf), true,
			key))) {
	/* TODO: If this failed, indicate to the caller that we
	 * couldn't pack the record. */
	App_ReportSysError(CryptoErrorAlert, err);
    }
	    
    return buf;
}


static Err KeyRecord_SetCategory(Int16 idx, UInt16 category) {
    UInt16		attr;
    Err			err;

    if ((err = DmRecordInfo(gKeyDB, idx, &attr, 0, 0)))
	return err;

    attr = (attr & ~dmRecAttrCategoryMask)
	| (category & dmRecAttrCategoryMask);

    return DmSetRecordInfo(gKeyDB, idx, &attr, 0);
}


Err KeyRecord_GetCategory(Int16 idx, UInt16 *category) {
    UInt16		attr;
    Err			err;

    if ((err = DmRecordInfo(gKeyDB, idx, &attr, 0, 0)))
	return err;

    *category = (attr & dmRecAttrCategoryMask);

    return 0;
}


void KeyRecord_SaveNew(UnpackedKeyType const *unpacked, Char const *name) {
    MemHandle	record;
    Int16		idx;
    UInt32	recLen;
    Err		err;
    void        *encBuf, *recPtr;
    
    // TODO: If empty, don't save
    encBuf = KeyRecord_Pack(unpacked, gRecordKey);
    recLen = MemPtrSize(encBuf);
    
    idx = DmFindSortPosition(gKeyDB, (Char *) name, 0,
			     KeyDB_CompareRecords, 0);
    record = DmNewRecord(gKeyDB, &idx, recLen);
    if (!record) {
	App_ReportSysError(KeyDatabaseAlert, DmGetLastErr());
	return;
    }
    gKeyRecordIndex = idx;
    
    recPtr = MemHandleLock(record);
    DmWrite(recPtr, 0, encBuf, recLen);
    MemHandleUnlock(record);
    MemPtrFree(encBuf);

    err = DmReleaseRecord(gKeyDB, idx, true); // dirty
    if (err)
	App_ReportSysError(KeyDatabaseAlert, err);

    KeyRecord_SetCategory(idx, unpacked->category);

    gKeyPosition = DmPositionInCategory(gKeyDB, idx, gPrefs.category);
}


void KeyRecord_Update(UnpackedKeyType const *unpacked,
		      UInt16 idx)
{
    MemHandle	record;
    UInt32	recLen;
    void *encBuf, *recPtr;
    Err		err;

    encBuf = KeyRecord_Pack(unpacked, gRecordKey);
    recLen = MemPtrSize(encBuf);
    
    record = DmResizeRecord(gKeyDB, idx, recLen);
    if (!record) {
	App_ReportSysError(KeyDatabaseAlert, DmGetLastErr());
	MemPtrFree(encBuf);
	return;
    }

    recPtr = MemHandleLock(record);
    DmWrite(recPtr, 0, encBuf, recLen);
    MemPtrFree(encBuf);
    
    if ((err = DmReleaseRecord(gKeyDB, idx, true)))
	App_ReportSysError(KeyDatabaseAlert, err);

    KeyRecord_SetCategory(idx, unpacked->category);
}

