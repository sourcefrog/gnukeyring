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

/*
 * TODO: Check that the terminating NULs in the strings are accounted
 * for correctly.
 *
 * TODO: Is it possible we could be overflowing the stack?
 */

#include "includes.h"
extern void *alloca(unsigned long size);

typedef struct {
    UInt16    version;
    UInt8     nameLen;
    UInt8     fontID;
} PackedKeyType;

typedef struct {
    UInt16    len;
    UInt8     labelID;
    UInt8     fontID;
} PackedFieldType;

#define EVEN(x) (((x)+1)&~1)
#define ENDMARKER 0xffff

Err Record_Unpack(MemHandle record, UnpackedKeyType **u, CryptoKey *recordKey)
{
    void          *recPtr;
    void          *plainBuf, *plainPtr;
    UInt8         ivec[recordKey->blockSize];
    UInt32        size, cryptSize;
    UInt16        fieldLen;
    UInt16        offset;
    UInt16        fieldCnt;

    recPtr = MemHandleLock(record);
    ErrFatalDisplayIf(!recPtr, "couldn't lock record");

    fieldLen = EVEN(* (UInt16 *) recPtr) + sizeof(FieldHeaderType);
    if ((UInt32)fieldLen + recordKey->blockSize > MemHandleSize(record)) {
        FrmCustomAlert(ID_KeyDatabaseAlert,
                       "record underflow", __FUNCTION__, "");
	MemHandleUnlock(record);
	return dmErrCorruptDatabase;
    }
    
    size = MemHandleSize(record) - recordKey->blockSize;
    plainBuf = MemPtrNew(size);
    if (plainBuf == NULL) {
	MemHandleUnlock(record);
	return memErrNotEnoughSpace;
    }

    plainPtr = plainBuf;
    MemMove(plainPtr, recPtr, fieldLen);
    plainPtr += fieldLen;
    recPtr   += fieldLen;
    offset    = fieldLen;

    MemMove(ivec, recPtr, recordKey->blockSize);
    recPtr += recordKey->blockSize;
    cryptSize = (size - fieldLen) & ~(recordKey->blockSize - 1);
    if (cryptSize)
	CryptoRead(recPtr, plainPtr, cryptSize, recordKey, ivec);

    /* Now count the fields */
    fieldCnt = 1;
    while (*(UInt16 *) plainPtr != ENDMARKER) {
	fieldLen = EVEN (*(UInt16 *) plainPtr) + sizeof(FieldHeaderType);
	if (offset + fieldLen + 2 > size) {
	    FrmCustomAlert(ID_KeyDatabaseAlert,
			   "record underflow", __FUNCTION__, "");
	    *(UInt16 *)plainPtr = ENDMARKER;
	    break;
	}

	plainPtr += fieldLen;
	offset   += fieldLen;
   	fieldCnt++;
    }

    *u = MemPtrNew(sizeof(UnpackedKeyType) + (fieldCnt -1) *sizeof(UInt16));

    if (*u == NULL) {
	MemWipe(plainBuf, size);
	MemPtrFree(plainBuf);
	MemHandleUnlock(record);
	return memErrNotEnoughSpace;
    }

    (*u)->numFields = fieldCnt;
    (*u)->plainText = plainBuf;

    plainPtr = plainBuf;
    fieldCnt = 0;
    offset = 0;
    while (*(UInt16 *) plainPtr != ENDMARKER) {
	(*u)->fieldOffset[fieldCnt++] = offset;

	fieldLen = EVEN (*(UInt16 *) plainPtr) + sizeof(FieldHeaderType);
	plainPtr += fieldLen;
	offset   += fieldLen;
    }

    MemHandleUnlock(record);
    return 0;
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
void Record_SaveRecord(UnpackedKeyType const *unpacked, UInt16 idx, 
		       CryptoKey *recordKey)
{
    MemHandle recHandle;
    void      *plainPtr, *recPtr;
    UInt8     *cryptPtr;
    UInt16    nameLen, lastOffset, size, bodySize, packSize;
    UInt8     ivec[recordKey->blockSize];
    UInt16    i, attr;
    
    plainPtr = unpacked->plainText;

    /* Calculate size */
    lastOffset = unpacked->fieldOffset[unpacked->numFields-1];
    nameLen  = EVEN(*(UInt16*)plainPtr) + sizeof(FieldHeaderType);
    bodySize = lastOffset + sizeof(FieldHeaderType)
	+ EVEN(*(UInt16*)(plainPtr+lastOffset)) + 2 - nameLen;
    packSize = (bodySize + recordKey->blockSize - 1)
	& ~(recordKey->blockSize - 1);
    size     = nameLen + recordKey->blockSize + packSize;

    recHandle = DmResizeRecord(gKeyDB, idx, size);
    if (!recHandle) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, DmGetLastErr(),
                           __FUNCTION__);
	return;
    }
    recPtr = MemHandleLock(recHandle);

    for (i = 0; i < recordKey->blockSize; i++) 
	ivec[i] = Secrand_GetByte();

    DmWrite (recPtr, 0, plainPtr, nameLen);
    DmWrite (recPtr, nameLen, ivec, recordKey->blockSize);
    cryptPtr = alloca(packSize);
    MemMove(cryptPtr, plainPtr + nameLen, bodySize);
    for (i = bodySize; i < packSize; i++)
	cryptPtr[i] = Secrand_GetByte();
    CryptoWrite(cryptPtr, cryptPtr, packSize, recordKey, ivec);
    DmWrite(recPtr, nameLen + recordKey->blockSize, cryptPtr, packSize);
    MemHandleUnlock(recHandle);
    if (DmRecordInfo(gKeyDB, idx, &attr, NULL, NULL) == 0) {
	attr = (attr & ~dmRecAttrCategoryMask) | unpacked->category;
	DmSetRecordInfo(gKeyDB, idx, &attr, NULL);
    }
}


/*
 * Frees record and all associated data.  Also overwrites everything
 * with zeros.
 */
void Record_Free(UnpackedKeyPtr u)
{
    if (u->plainText) {
	MemWipe(u->plainText, MemPtrSize(u->plainText));
	MemPtrFree(u->plainText);
    }
    MemWipe(u, MemPtrSize(u));
    MemPtrFree(u);
}

Err Record_SetField(UnpackedKeyPtr record, UInt16 idx, 
		    void *data, UInt16 len) {
    UInt8 *dest;
    UInt16 i;
    FieldHeaderType *fldHeader;
    UInt16 fldLen;

    fldHeader = (FieldHeaderType *)
	(record->plainText + record->fieldOffset[idx]);
    fldLen = fldHeader->len;

    if (EVEN(len) != EVEN(fldLen)) {
	/* Resize record */
	int diff = EVEN(len) - EVEN(fldLen);
	UInt16 oldSize  = MemPtrSize(record->plainText);
	UInt16 offset;
	void *newText   = MemPtrNew(oldSize + diff);

	if (!newText)
	    return memErrNotEnoughSpace;

	offset = record->fieldOffset[idx] + sizeof(FieldHeaderType);
	MemMove(newText, record->plainText, offset);
	MemMove(newText + offset + EVEN(len),
		record->plainText + offset + EVEN(fldLen),
		oldSize - offset - EVEN(fldLen));
	for (i = idx + 1; i < record->numFields; i++)
	    record->fieldOffset[i] += diff;
	MemWipe(record->plainText, oldSize);
	MemPtrFree(record->plainText);
	record->plainText = newText;
	fldHeader = (FieldHeaderType *)
	    (record->plainText + record->fieldOffset[idx]);
    }

    fldHeader->len = len;
    dest = (UInt8*) (record->plainText
		     + record->fieldOffset[idx]
		     + sizeof(FieldHeaderType));
    MemMove(dest, data, len);
    /* pad with zero */
    if ((len & 1))
	dest[len] = 0;

    return 0;
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
