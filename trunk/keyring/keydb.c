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
#include "keydb.h"
#include "crypto.h"
#include "record.h"
#include "passwd.h"
#include "resource.h"

Int16 gKeyDBCardNo;
LocalID gKeyDBID;

static Err KeyDB_OpenRingInfo(KeyringInfoPtr *);

// ======================================================================
// Key database



static void KeyDB_HashNewPasswd(Char const *newPasswd,
				KeyringInfoPtr ai)
{
    Char msgBuf[64];
    Char * ptr;
    Err err;
    
    ai->passwdSalt = ((UInt32) SysRandom(0) << 16L) | SysRandom(0);

    MemSet(msgBuf, 64, 0);
    ptr = msgBuf;
    MemMove(ptr, &ai->passwdSalt, sizeof(Int32));
    ptr += sizeof(Int32);
    StrNCopy(ptr, newPasswd, 64 - 1 - sizeof(Int32));

    err = EncDigestMD5(msgBuf, 64, ai->passwdHash);
    if (err)
	App_ReportSysError(CryptoErrorAlert, err);
}


static Boolean KeyDB_CheckPasswdHash(Char const *guess, KeyringInfoPtr ki) {
    Char msgBuf[64];
    UInt8 guessHash[kPasswdHashSize];
    Char * ptr;
    Err err;
    
    MemSet(msgBuf, 64, 0);
    ptr = msgBuf;
    MemMove(ptr, &ki->passwdSalt, sizeof(Int32));
    ptr += sizeof(Int32);
    StrNCopy(ptr, guess, 64 - 1 - sizeof(Int32));

    err = EncDigestMD5(msgBuf, 64, guessHash);
    if (err)
	App_ReportSysError(CryptoErrorAlert, err);

    return !MemCmp(guessHash, &ki->passwdHash[0], kPasswdHashSize);
}


/* Return a locked pointer to the ring info block stored in the
 * database's SortInfo pointer. */
Err KeyDB_CreateRingInfo(void) {
    LocalID		KeyringInfoID;
    MemHandle		KeyringInfoHand;
    Err			err;

    KeyringInfoHand = DmNewHandle(gKeyDB, sizeof(KeyringInfoType));
    KeyringInfoID = MemHandleToLocalID(KeyringInfoHand);
    
    if ((err = DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
				 0, 0, 0, 0,
				 0, 0, 0,
				 0, &KeyringInfoID, 0, 0)))
	return err;

    return 0;
}


Err KeyDB_CreateCategories(void) {
    LocalID		appInfoID;
    MemHandle h;
    AppInfoPtr		appInfoPtr;

    if (DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0, 0, 0,
		       0, 0, 0,
		       &appInfoID, 0, 0, 0))
	return dmErrInvalidParam;

    if (appInfoID == 0) {
	h = DmNewHandle(gKeyDB, sizeof(AppInfoType));
	if (!h)
	    return DmGetLastErr();
                
	appInfoID = MemHandleToLocalID(h);
	DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			  0,0,0,0,
			  0,0,0,
			  &appInfoID, 0,0,0);
    }
    appInfoPtr = MemLocalIDToLockedPtr(appInfoID, gKeyDBCardNo);

    /* Clear the app info block. */
    DmSet(appInfoPtr, 0, sizeof(AppInfoType), 0);

    /* Initialize the categories. */
    CategoryInitialize(appInfoPtr, CategoryRsrc);

    MemPtrUnlock(appInfoPtr);

    return 0;
}


/* Store the checking-hash of a password into the database info. */
static Err KeyDB_StorePasswdHash(Char const *newPasswd) {
    KeyringInfoPtr	dbPtr;
    KeyringInfoType		kiBuf;
    Err			err;

    if ((err = KeyDB_OpenRingInfo(&dbPtr)))
	return err;
    
    MemSet(&kiBuf, sizeof(kiBuf), 0);
    kiBuf.appInfoVersion = kAppVersion;	/* no longer checked, here for compatibility */
    KeyDB_HashNewPasswd(newPasswd, &kiBuf);
    DmWrite(dbPtr, 0, (void *) &kiBuf, sizeof(kiBuf));
    MemPtrUnlock(dbPtr);

    return 0;
}


/* Called after setting the password: walks through the database
 * changing the encryption of each record to suit the new key.
 *
 * This method must be called with the old unlock hash still
 * present in memory. */
/* XXX: It would be REALLY BAD if this failed: we've changed the encryption
 * on some record, but not others.  This will mean the
 * user can't decrypt some of them.  We need a systematic
 * way around this.
 *
 * Probably a good way is to not use the key to really encrypt the
 * records, but rather an invariant session key.  */
static void KeyDB_Reencrypt(Char const *newPasswd) {
    /* We read each record into memory, decrypt it using the old
     * unlock hash, then encrypt it using the new hash and write it
     * back. */
    UInt16 	numRecs = DmNumRecords(gKeyDB);
    UInt16 	idx;
    MemHandle 	fromRec;
    void	*recPtr, *toPtr;
    UInt16	attr;
    Err		err;
    UnpackedKeyType	unpacked;
    UInt32		recLen;
    UInt8		newRecordKey[kPasswdHashSize];

    err = EncDigestMD5((void *) newPasswd,
		       StrLen(newPasswd),
		       newRecordKey);
    if (err)
	App_ReportSysError(CryptoErrorAlert, err);

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

	UnpackedKey_Free(&unpacked);

	DmReleaseRecord(gKeyDB, idx, true); // dirty
    }

    // Finally, make the new unlock hash the currently active one
    MemMove(gRecordKey, newRecordKey, kPasswdHashSize);
}


void KeyDB_SetPasswd(Char const *newPasswd) {
    KeyDB_Reencrypt(newPasswd);
    KeyDB_StorePasswdHash(newPasswd);
    Unlock_PrimeTimer();
}





/* Return locked pointer to keyring info; or null if there is no
 * keyring info present.  The pointer is into the database, so it
 * can't be written directly, only through DmWrite and friends. */
Err KeyDB_OpenRingInfo(KeyringInfoPtr *pp) {
    LocalID		kiID;
    Err			err;

    *pp = 0;

    err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			 NULL, NULL, NULL, NULL, NULL,
			 NULL, NULL, 0, &kiID, NULL, NULL);
    if (err)
	return err;

    if (!kiID)
	return 0;

    *pp = (KeyringInfoPtr) MemLocalIDToLockedPtr(kiID, gKeyDBCardNo);

    return 0;
}


Boolean KeyDB_Verify(Char const *guess) {
    KeyringInfoPtr	ptr;
    Boolean    		result;
    Err			err;

    err = KeyDB_OpenRingInfo(&ptr);
    result = KeyDB_CheckPasswdHash(guess, ptr);
    MemPtrUnlock(ptr);
    return result;
}


/* Will return an error if the database does not exist. */
Err KeyDB_OpenExistingDB(DmOpenRef *dbp) {
    Err err;
    
    // TODO: Give people the option to name the database, or to create
    // it on different cards?
    *dbp = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
				       dmModeReadWrite);
    if (!*dbp)
	return DmGetLastErr();

    if ((err = DmOpenDatabaseInfo(*dbp, &gKeyDBID, NULL, NULL, &gKeyDBCardNo, NULL)))
	return err;

    return 0;
}


Err KeyDB_SetVersion(void) {
    UInt16 version = kDatabaseVersion;
    return DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			     NULL, NULL,
			     &version,
			     NULL, NULL, NULL, NULL,
			     NULL, NULL, NULL, NULL);
}


Err KeyDB_CreateDB(void) {
    Err err;

    gKeyDBCardNo = 0;
    if ((err = DmCreateDatabase(gKeyDBCardNo, kKeyDBName,
				kKeyringCreatorID, kKeyDBType,
				false /* not resource */)))
	return err;

    gKeyDBID = DmFindDatabase(gKeyDBCardNo, kKeyDBName);
    if (!gKeyDBID) {
	return DmGetLastErr();
    }

    if ((err = KeyDB_SetVersion()))
	return err;

    return 0;
}


Err KeyDB_MarkForBackup(void) {
    UInt16 attr;
    
    // Set the backup bit.  It seems that without this the Windows
    // desktop software doesn't make the backup properly

    /* TODO: Here or elsewhere set the database version! */
    
    DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL, &attr, NULL, NULL,
		   NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    attr |= dmHdrAttrBackup;
    DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL, &attr, NULL, NULL,
		      NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    return 0;
}


Err KeyDB_GetVersion(UInt16 *ver) {
    return DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0,
			  ver,
			  0, 0, 0, 0,
			  0, 0, 0, 0);
}

