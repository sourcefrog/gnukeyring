/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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
extern void *alloca(unsigned long size);
#define EVEN(x) (((x)+1)&~1)

/*
 * TODO: Create a shadow database and only if that succeeds remove
 * old database and rename new one.
 */

static REENCRYPT_SECTION
Err SetPasswd_ReencryptRecords(CryptoKey *oldRecordKey, 
			       CryptoKey *newRecordKey, 
			       DmOpenRef newKeyDB)
{
    UInt16 	numRecs = DmNumRecords(gKeyDB);
    UInt16	attr, idx, newIdx;
    UInt32	uniqueID;
    MemHandle	oldRecH, newRecH;
    void	*oldRecPtr, *newRecPtr;
    UInt8       *plainBuf;
    UInt16      maxBlockSize = 
	oldRecordKey->blockSize > newRecordKey->blockSize
	? oldRecordKey->blockSize : newRecordKey->blockSize;
    UInt8       ivec[maxBlockSize];
    UInt16      plainBufSize;
    UInt32      off, size, newsize, i;
    Err         err;

    plainBufSize = 128;
    plainBuf = MemPtrNew(plainBufSize);
    if (!plainBuf) {
	return memErrNotEnoughSpace;
    }

    for (idx = kNumHiddenRecs; idx < numRecs; idx++) {
	/* Skip deleted records.  Handling of archived records is a
	 * bit of an open question, because we'll still want to be
	 * able to decrypt them on the PC.  (If we can ever do
	 * that...)
	 */
	err = DmRecordInfo(gKeyDB, idx, &attr, &uniqueID, NULL);
	if (err)
	    goto outErr;
	if ((attr & dmRecAttrDelete))
	    continue;

	/* Open record */
	oldRecH = DmQueryRecord(gKeyDB, idx);
        if (!oldRecH) {
	    err = DmGetLastErr();
	    goto outErr;
	}
        oldRecPtr = MemHandleLock(oldRecH);

	/* Get the offset and size of the encrypted block */
	off = EVEN(* (UInt16 *) oldRecPtr) + sizeof(FieldHeaderType);
	size = MemPtrSize(oldRecPtr) - off - oldRecordKey->blockSize;
	if (off + oldRecordKey->blockSize > MemPtrSize(oldRecPtr)
	    || (size & (oldRecordKey->blockSize-1))) {
	    err = dmErrCorruptDatabase;
	    goto outErr;
	}
	newsize = (size + newRecordKey->blockSize - 1)
	    & ~(newRecordKey->blockSize - 1);

	if (newsize > plainBufSize) {
	    MemWipe(plainBuf, plainBufSize);
	    MemPtrFree(plainBuf);
	    plainBufSize = newsize;
	    plainBuf = MemPtrNew(plainBufSize);
	    if (!plainBuf) {
		err = memErrNotEnoughSpace;
		goto outErr;
	    }
	}

	MemMove(ivec, oldRecPtr + off, oldRecordKey->blockSize);
	CryptoRead(oldRecPtr + off + oldRecordKey->blockSize, plainBuf, size, 
		   oldRecordKey, ivec);

	newIdx = dmMaxRecordIndex;
	newRecH = DmNewRecord(newKeyDB, &newIdx, 
			      off + newRecordKey->blockSize + newsize);
	if (!newRecH) {
	    err = DmGetLastErr();
	    goto outErr;
	}
	
	/* Preserve attributes, categories and unique id */
	DmSetRecordInfo(newKeyDB, newIdx, &attr, &uniqueID);
        newRecPtr = MemHandleLock(newRecH);
	for (i = 0; i < newRecordKey->blockSize; i++) 
	    ivec[i] = Secrand_GetByte();
	for (i = size; i < newsize; i++)
	    plainBuf[i] = Secrand_GetByte();
	DmWrite(newRecPtr, 0, oldRecPtr, off);
	DmWrite(newRecPtr, off, ivec, newRecordKey->blockSize);
	CryptoWrite(plainBuf, plainBuf, newsize, newRecordKey, ivec);
	DmWrite(newRecPtr, off + newRecordKey->blockSize, plainBuf, newsize);
	MemHandleUnlock(newRecH);
	MemHandleUnlock(oldRecH);
	DmReleaseRecord(newKeyDB, newIdx, true);
    }

    err = 0;
    outErr:
    /* Erase and free plainBuf */
    MemWipe(plainBuf, plainBufSize);
    MemPtrFree(plainBuf);
    return err;
}

/*
 * Walk through the database, and for each record decrypt it using the
 * old session key from the snib, and then store it back encrypted by
 * the new session key.  Finally update the snib to hold the hash of
 * the new password.
 *
 * We now no longer bother unpacking each record, but rather make a
 * single pass through converting packed record.  This is simpler and
 * saves space.
 *
 * We do have to also include archived records, as they must be
 * accessible on the PC.
 */
REENCRYPT_SECTION 
void SetPasswd_Reencrypt(CryptoKey *oldRecordKey, 
			 Char *newPassword, UInt16 cipher, UInt16 iter)
{
    /* We read each record into memory, decrypt it using the old
     * unlock hash, then encrypt it using the new hash and write it
     * back. */
    Err		 err;
    CryptoKey    *newRecordKey;
    SaltHashType salthash;
    LocalID      newKeyDBID;
    DmOpenRef    newKeyDB;
    LocalID      clearAppInfo, appInfo;
    UInt16       version;
    UInt32       type;

    newRecordKey = MemPtrNew(sizeof(CryptoKey));
    if (!newRecordKey) {
	err = memErrNotEnoughSpace;
	goto outErr0;
    }

    if ((err = PwHash_Create(newPassword, cipher, iter, 
			     &salthash, newRecordKey))) {
	FrmCustomAlert(NotEnoughFeaturesAlert, "crypto library", NULL, NULL);
	MemPtrFree(newRecordKey);
	return;
    }

    newKeyDBID = DmFindDatabase(gKeyDBCardNo, kKeyDBTempName);
    if (newKeyDBID)
	DmDeleteDatabase(gKeyDBCardNo, newKeyDBID);

    if ((err = DmCreateDatabase(gKeyDBCardNo, kKeyDBTempName,
				kKeyringCreatorID, kKeyDBTempType,
				false /* not resource */)))
	goto outErr;

    newKeyDBID = DmFindDatabase(gKeyDBCardNo, kKeyDBTempName);
    if (!newKeyDBID) {
	err = DmGetLastErr();
	goto outErr;
    }

    newKeyDB = DmOpenDatabase(gKeyDBCardNo, newKeyDBID, dmModeReadWrite);
    if (!newKeyDB) {
	err = DmGetLastErr();
	goto outErr1;
    }

    err = SetPasswd_ReencryptRecords(oldRecordKey, newRecordKey, newKeyDB);

    if (!err) {
	appInfo = DmGetAppInfoID(gKeyDB);
	DmCloseDatabase(gKeyDB);
	clearAppInfo = 0;
	DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL,
			  NULL, NULL, NULL, NULL,
			  NULL, NULL, &clearAppInfo, NULL,
			  NULL, NULL);
	
	DmDeleteDatabase(gKeyDBCardNo, gKeyDBID);
    
	gKeyDBID = newKeyDBID;
	gKeyDB = newKeyDB;
	version = kDatabaseVersion;
	type = kKeyDBType;
	DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID, kKeyDBName,
			  NULL, &version, NULL, NULL,
			  NULL, NULL, &appInfo, NULL,
			  &type, NULL);
	PwHash_Store(newPassword, &salthash);
	MemWipe(&salthash, sizeof(salthash));
	MemWipe(&newRecordKey, sizeof(newRecordKey));
	return;
    }
    
    DmCloseDatabase(newKeyDB);
    outErr1:
    DmDeleteDatabase(gKeyDBCardNo, newKeyDBID);
    outErr:
    CryptoDeleteKey(newRecordKey);
    MemPtrFree(newRecordKey);
    outErr0:
    MemWipe(&salthash, sizeof(salthash));

    /* Complain about errors now. */
    ErrAlert(err);
}
