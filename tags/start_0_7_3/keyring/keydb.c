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
#include "memutil.h"
#include "keydb.h"
#include "crypto.h"
#include "passwd.h"

static Int KeyDB_CompareRecords(VoidPtr rec1, VoidPtr rec2, Int other,
			 SortRecordInfoPtr info1,
			 SortRecordInfoPtr info2,
			 VoidHand appInfoHand);
static KeyringInfoPtr KeyDB_OpenKeyringInfo(void);

// ======================================================================
// Key record manipulation


/* Calculate the size a record will occupy when it is packed. */
static ULong KeyRecord_CalcPackedLength(UnpackedKeyType const *unpacked)
{
    ULong plainSize = unpacked->nameLen + 1;
    ULong encSize = unpacked->acctLen + 1
	+ unpacked->passwdLen + 1
	+ unpacked->notesLen + 1
	+ sizeof(ULong);		/* date */

    /* All the fields except for the name are encrypted into DES
     * 8-byte blocks, so we have to round up to the next full block
     * size. */
    if (encSize & (kBlockSize-1))
	encSize = (encSize & ~(kBlockSize-1)) + kBlockSize;

    return encSize + plainSize;
}


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


static void UnpackedKey_Free(UnpackedKeyPtr u) {
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
 * representation. */
void KeyRecord_Unpack(VoidHand record, UnpackedKeyType *u,
		      Byte const *key)
{
    CharPtr	recPtr = MemHandleLock(record);
    CharPtr	plainBuf;
    CharPtr	cryptPtr;
    ULong	recLen;
    CharPtr	ptr;
    Long	nameLen;
    
    u->nameHandle = Mem_StrToHandle(recPtr, &nameLen);
    u->nameLen = nameLen;

    recLen = MemHandleSize(record);
    plainBuf = MemPtrNew(recLen);
    ErrFatalDisplayIf(!plainBuf, __FUNCTION__ ": couldn't allocate plainBuf");
    cryptPtr = recPtr + nameLen + 1;
    DES3_Buf(cryptPtr, plainBuf, recLen - (cryptPtr - recPtr), false,
	     key);

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
static VoidPtr KeyRecord_Pack(UnpackedKeyType const *u,
			      Byte const *key)
{
    int		dateLen;
    CharPtr	ptr; // Moves through buffer filling with data
    CharPtr     startCrypt;     // Start of data that should be enc.
    CharPtr     buf; // Start of buffer
    ULong	recLen;
    
    recLen = KeyRecord_CalcPackedLength(u);
    buf = MemPtrNew(recLen);
    ErrFatalDisplayIf(!buf, __FUNCTION__ ": new encBuf");
    ptr = buf;

    Mem_CopyFromHandle(&ptr, u->nameHandle, u->nameLen+1);
    startCrypt = ptr;

    Mem_CopyFromHandle(&ptr, u->acctHandle, u->acctLen+1);
    Mem_CopyFromHandle(&ptr, u->passwdHandle, u->passwdLen+1);
    Mem_CopyFromHandle(&ptr, u->notesHandle, u->notesLen+1);

    dateLen = sizeof(DateType);
    MemMove(ptr, (VoidPtr) &u->lastChange, dateLen);
    ptr += dateLen;

    DES3_Buf(startCrypt, startCrypt, recLen - (startCrypt-buf), true,
	     key);
	    
    return buf;
}


// ======================================================================
// Key database


/* Compare records for sorting or sorted insertion.
 *
 * Because all records begin with the strz record name the comparison
 * is pretty simple: we sort in string order, except that deleted
 * records go to the end.  */
static Int KeyDB_CompareRecords(VoidPtr rec1, VoidPtr rec2,
				Int other UNUSED,
				SortRecordInfoPtr info1,
				SortRecordInfoPtr info2,
				VoidHand appInfoHand UNUSED)
{
    Int result;
    CharPtr	cp1, cp2;

    CALLBACK_PROLOGUE;
    if (info1 && (info1->attributes & dmRecAttrDelete))
	result = +1;
    else if (info2 && (info2->attributes & dmRecAttrDelete))
	result = -1;
    else {
	cp1 = (CharPtr) rec1;
	cp2 = (CharPtr) rec2;
	
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
    CALLBACK_EPILOGUE;
    return result;
}


static void KeyDB_HashNewPasswd(Char const *newPasswd,
				KeyringInfoPtr ai)
{
    Char msgBuf[64];
    CharPtr ptr;
    Err err;
    
    ai->passwdSalt = ((ULong) SysRandom(0) << 16L) | SysRandom(0);

    MemSet(msgBuf, 64, 0);
    ptr = msgBuf;
    MemMove(ptr, &ai->passwdSalt, sizeof(Long));
    ptr += sizeof(Long);
    StrNCopy(ptr, newPasswd, 64 - 1 - sizeof(Long));

    err = EncDigestMD5(msgBuf, 64, ai->passwdHash);
    if (err)
	App_ReportSysError(__FUNCTION__, err);
}


static Boolean KeyDB_CheckPasswdHash(Char const *guess, KeyringInfoPtr ki) {
    Char msgBuf[64];
    Byte guessHash[kPasswdHashSize];
    CharPtr ptr;
    Err err;
    
    MemSet(msgBuf, 64, 0);
    ptr = msgBuf;
    MemMove(ptr, &ki->passwdSalt, sizeof(Long));
    ptr += sizeof(Long);
    StrNCopy(ptr, guess, 64 - 1 - sizeof(Long));

    err = EncDigestMD5(msgBuf, 64, guessHash);
    if (err)
	App_ReportSysError("hash passwd", err);

    return !MemCmp(guessHash, &ki->passwdHash[0], kPasswdHashSize);
}


void KeyDB_CreateAppInfo(void) {
    LocalID		KeyringInfoID, dbID;
    UInt		cardNo;
    VoidHand		KeyringInfoHand;
    Err			err;

    err = DmOpenDatabaseInfo(gKeyDB, &dbID, NULL, NULL, &cardNo, NULL);
    if (err)
	App_ReportSysError("get db location", err);
    
    KeyringInfoHand = DmNewHandle(gKeyDB, sizeof(KeyringInfoType));
    KeyringInfoID = MemHandleToLocalID(KeyringInfoHand);
    
    DmSetDatabaseInfo(cardNo, dbID, 0, 0, 0, 0, 0, 0, 0,
		      &KeyringInfoID, 0, 0, 0);
}


/* Store the checking-hash of a password into the database info. */
static void KeyDB_StorePasswdHash(Char const *newPasswd) {
    KeyringInfoPtr	dbPtr;
    KeyringInfoType		kiBuf;

    dbPtr = KeyDB_OpenKeyringInfo();
    ErrNonFatalDisplayIf(!dbPtr, "no keyringinfo");
    MemSet(&kiBuf, sizeof(kiBuf), 0);
    kiBuf.appInfoVersion = kKeyringVersion;
    KeyDB_HashNewPasswd(newPasswd, &kiBuf);
    DmWrite(dbPtr, 0, (VoidPtr) &kiBuf, sizeof(kiBuf));
    MemPtrUnlock(dbPtr);
}


/* Called after setting the password: walks through the database
 * changing the encryption of each record to suit the new key.
 *
 * This method must be called with the old unlock hash still
 * present in memory. */
static void KeyDB_Reencrypt(Char const *newPasswd) {
    /* We read each record into memory, decrypt it using the old
     * unlock hash, then encrypt it using the new hash and write it
     * back. */
    UInt 	numRecs = DmNumRecords(gKeyDB);
    UInt 	idx;
    VoidHand 	fromRec;
    VoidPtr	recPtr, toPtr;
    UInt	attr;
    Err		err;
    UnpackedKeyType	unpacked;
    ULong		recLen;
    Byte		newRecordKey[kPasswdHashSize];

    err = EncDigestMD5((VoidPtr) newPasswd,
		       StrLen(newPasswd),
		       newRecordKey);
    if (err)
	App_ReportSysError("md5", err);

    for (idx = 0; idx < numRecs; idx++) {
	// Skip deleted records.  Handling of archived records is a
	// bit of an open question, because we'll still want to be
	// able to decrypt them on the PC.  (If we can ever do
	// that...)
	err = DmRecordInfo(gKeyDB, idx, &attr, NULL, NULL);
	ErrFatalDisplayIf(err, "DmRecordInfo");
	if (attr & (dmRecAttrDelete | dmRecAttrSecret))
	    continue;

	// Open read-only and read in to memory
	fromRec = DmQueryRecord(gKeyDB, idx);
	ErrFatalDisplayIf(!fromRec, "couldn't query record");

	// Read into a temporary unpacked buffer
	KeyRecord_Unpack(fromRec, &unpacked, gRecordKey);
	
	// Pack and encrypt using the new key
	toPtr = KeyRecord_Pack(&unpacked, newRecordKey);
	ErrNonFatalDisplayIf(!toPtr, "!toPtr");

	// Now resize record to fit packed size	
	recLen = MemPtrSize(toPtr);
	ErrNonFatalDisplayIf(!recLen, "!recLen");

	fromRec = DmResizeRecord(gKeyDB, idx, recLen);
	ErrNonFatalDisplayIf(!fromRec, "resize failed");

	recPtr = MemHandleLock(fromRec);
	ErrNonFatalDisplayIf(!recPtr, "!recPtr");
	DmWrite(recPtr, 0, toPtr, recLen);
	MemHandleUnlock(fromRec);
	MemPtrFree(toPtr);

	DmReleaseRecord(gKeyDB, idx, true); // dirty
	UnpackedKey_Free(&unpacked);
    }

    // Finally, make the new unlock hash the currently active one
    MemMove(gRecordKey, newRecordKey, kPasswdHashSize);
}


void KeyDB_SetPasswd(Char const *newPasswd) {
    KeyDB_Reencrypt(newPasswd);
    KeyDB_StorePasswdHash(newPasswd);
    Unlock_PrimeTimer();
}


void KeyDB_SaveNewRecord(UnpackedKeyType const *unpacked, Char const *name) {
    VoidHand	record;
    Int		idx;
    ULong	recLen;
    Err		err;
    VoidPtr	encBuf, recPtr;
    
    // TODO: If empty, don't save
    encBuf = KeyRecord_Pack(unpacked, gRecordKey);
    recLen = MemPtrSize(encBuf);
    
    idx = DmFindSortPosition(gKeyDB, (CharPtr) name, 0,
			     KeyDB_CompareRecords, 0);
    ErrNonFatalDisplayIf(!gKeyDB, "save new key: no database");
    record = DmNewRecord(gKeyDB, &idx, recLen);
    if (!record) {
	err = DmGetLastErr();
	App_ReportSysError(__FUNCTION__ ":new", err);
	return;
    }
    gKeyRecordIndex = idx;
    
    recPtr = MemHandleLock(record);
    DmWrite(recPtr, 0, encBuf, recLen);
    MemHandleUnlock(record);
    MemPtrFree(encBuf);

    err = DmReleaseRecord(gKeyDB, idx, true); // dirty
    if (err)
	App_ReportSysError(__FUNCTION__ ":release", err);
}


void KeyDB_UpdateRecord(UnpackedKeyType const *unpacked,
			UInt idx)
{
    VoidHand	record;
    Err 	err;
    ULong	recLen;
    VoidPtr	encBuf, recPtr;

    encBuf = KeyRecord_Pack(unpacked, gRecordKey);
    recLen = MemPtrSize(encBuf);
    
    record = DmResizeRecord(gKeyDB, idx, recLen);
    if (!record) {
	err = DmGetLastErr();
	App_ReportSysError(__FUNCTION__ ":resize", err);
	goto leave;
    }

    recPtr = MemHandleLock(record);
    DmWrite(recPtr, 0, encBuf, recLen);    
    err = DmReleaseRecord(gKeyDB, idx, true); // dirty

    if (err)
	App_ReportSysError(__FUNCTION__ ": release", err);

 leave:
    MemPtrFree(encBuf);
}


void KeyDB_RepositionRecord(CharPtr name,
			    UIntPtr idx)
{
    Word 	attr;
    ULong 	uniqueID;
    Handle	moveHandle;
    Err 	err;
    
    DmRecordInfo(gKeyDB, *idx, &attr, &uniqueID, NULL);
    err = DmDetachRecord(gKeyDB, *idx, &moveHandle);
    if (err) {
	App_ReportSysError(__FUNCTION__ ":detach", err);
	return;
    }
	
    *idx = DmFindSortPosition(gKeyDB, (VoidPtr) name, 0,
			      KeyDB_CompareRecords, 0);

    err = DmAttachRecord(gKeyDB, idx, moveHandle, 0);
    if (err) {
	App_ReportSysError(__FUNCTION__ ":attach", err);
	return;
    }
    DmSetRecordInfo(gKeyDB, *idx, &attr, &uniqueID);
}


/* Return locked pointer to keyring info; or null if there is no
 * keyring info present.  The pointer is into the database, so it
 * can't be written directly, only through DmWrite and friends. */
static KeyringInfoPtr KeyDB_OpenKeyringInfo(void) {
    LocalID		kiID, dbID;
    UInt		cardNo;
    Err			err;
    VoidPtr		ptr;

    err = DmOpenDatabaseInfo(gKeyDB, &dbID, NULL, NULL, &cardNo, NULL);
    if (err)
	App_ReportSysError("get db location", err);
    
    err = DmDatabaseInfo(cardNo, dbID, NULL, NULL, NULL, NULL, NULL,
			 NULL, NULL, &kiID, NULL, NULL, NULL);
    if (err)
	App_ReportSysError("get db info", err);

    if (!kiID)
	return NULL;

    ptr = MemLocalIDToLockedPtr(kiID, cardNo);
    ErrNonFatalDisplayIf(!ptr, "!ptr");
    return (KeyringInfoPtr) ptr;
}


/* Check whether the key db is empty and must be initialized.  At present
 * this means there is no app info block.  Users are required to set
 * a password when first starting up. */
Boolean KeyDB_IsInitRequired(void) {
    KeyringInfoPtr	ptr;
    Boolean    		result;

    ptr = KeyDB_OpenKeyringInfo();
    if (!ptr)
	return true;
    if (MemPtrSize(ptr) < sizeof(KeyringInfoType)) {
	// Must be an old version with less configuration information,
	// so we'll have to upgrade.
	result = true;
    } else if (ptr->appInfoVersion != kKeyringVersion) {
	result = true;
    } else {
	// Must be OK
	result = false;
    }
    
    MemPtrUnlock(ptr);
    return result;    
}


Boolean KeyDB_Verify(Char const *guess) {
    KeyringInfoPtr	ptr;
    Boolean    		result;

    ptr = KeyDB_OpenKeyringInfo();
    ErrNonFatalDisplayIf(!ptr, "no keyringinfo");
    result = KeyDB_CheckPasswdHash(guess, ptr);
    MemPtrUnlock(ptr);
    return result;
}


/* Will return an error if the database does not exist. */
Err KeyDB_OpenExistingDB(DmOpenRef *dbp) {
    // TODO: Give people the option to name the database, or to create
    // it on different cards?
    *dbp = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
				       dmModeReadWrite);
    if (*dbp)
	return 0;
    else
	return DmGetLastErr();
}


Err KeyDB_CreateDB(DmOpenRef *dbp) {
    Err err;

    err = DmCreateDatabase(0, kKeyDBName, kKeyringCreatorID, kKeyDBType,
			   false /* not resource */);
    if (err)
	return err;

    *dbp = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
				       dmModeReadWrite);
    if (!*dbp)
	return DmGetLastErr();
    else
	return 0;
}
