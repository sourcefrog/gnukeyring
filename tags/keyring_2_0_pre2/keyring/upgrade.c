/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2002-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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


/* Some constants for old keyring version */
#define kOldMessageBufSize 64
#define kOldSaltSize        4
#define kMD5HashSize MD5_DIGEST_LENGTH

/* The old salt, hash and crypto structures */
typedef struct {
    Char salt[4];
    Char hash[16];
} OldCheckHashType;
typedef des_key_schedule OldCryptoKey[2];

/* We want a fixed size unpacked key type */
typedef struct {
    UnpackedKeyType unpacked;
    UInt16          moreFieldOffsets[4];
} SimpleUnpackedKeyType;

/* These definition are copied from record.c 
 * Should we put them into record.h ???
 */
typedef struct {
    UInt16    len;
    UInt8     labelID;
    UInt8     fontID;
} PackedFieldType;
#define ENDMARKER 0xffff



/*
 * TODO: In the future, when converting the database, write out to a
 * new database so that if something goes wrong we won't be lost.
 *
 */

static UPGRADE_SECTION void UpgradeDB_Failed(int oldVersion)
{
    char oldVer[8];
    StrIToA(oldVer, oldVersion);
    FrmCustomAlert(CantUpgradeAlert, oldVer, "", "");
}



static UPGRADE_SECTION Err Upgrade_From0(OldCheckHashType *hash)
{
    /* Copy the Hash from AppInfo block */
    LocalID appInfoID;
    Err err;
    void *hashPtr;
    
    if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0,
			      0, 0, 0, 0,
			      &appInfoID, 0,
			      0, 0)))
	return err;
    hashPtr = MemLocalIDToLockedPtr(appInfoID, gKeyDBCardNo);
    if (!hashPtr)
	return DmGetLastErr();
    MemMove(hash, hashPtr, sizeof(OldCheckHashType));
    MemPtrUnlock(hashPtr);
    return 0;
}


/*
 * Upgrade from a version 1 database.  We move the SortInfo data to hash.  
 */
static UPGRADE_SECTION Err Upgrade_From1(OldCheckHashType *hash)
{
    LocalID sortInfoID, appInfoID;
    Err err;
    void *hashPtr;
    
    if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0, 0, 0, 0, 0,
			      &appInfoID, &sortInfoID,
			      0, 0)))
	return err;
    
    if (sortInfoID == 0)
	return appErrMissingHash;

    hashPtr = MemLocalIDToLockedPtr(sortInfoID, gKeyDBCardNo);
    if (!hashPtr)
	return DmGetLastErr();
    MemMove(hash, hashPtr, sizeof(OldCheckHashType));
    MemPtrUnlock(hashPtr);
    return 0;
}


/*
 * Upgrade from a version 1 database.  We move the SortInfo data to
 * record 0, and set the appropriate attributes on that record.  The
 * AppInfo area should already contain appropriate category
 * information.
 *
 * The database version is updated on successful return.
 */
static UPGRADE_SECTION Err Upgrade_From4(OldCheckHashType *hash)
{
    UInt16 len = DmNumRecords(gKeyDB);
    UInt16 i;
    UInt16 recAttr;
    MemHandle recHandle;
    void     *recPtr;
    /* Search hidden record, it should be the first, but some
     * backup programs scramble order.
     */
    for (i = 0; i < len; i++) {
	if (DmRecordInfo(gKeyDB, i, &recAttr, NULL, NULL) == errNone
	    && (recAttr & dmRecAttrSecret)) {
	    recHandle = DmQueryRecord(gKeyDB, i);
	    if (MemHandleSize(recHandle) >= sizeof(OldCheckHashType)) {
		recPtr = MemHandleLock(recHandle);
		MemMove(hash, recPtr, sizeof(OldCheckHashType));
		MemHandleUnlock(recHandle);
		return 0;
	    }
	}
    }
    return appErrMissingHash;
}

static UPGRADE_SECTION 
Boolean Upgrade_CheckPwHash(char *passwd, OldCheckHashType *hash) {
    UInt8 buffer[kOldMessageBufSize];
    UInt8 digest[kMD5HashSize];
    UInt8 pwlen;
    MemMove(buffer, hash->salt, kOldSaltSize);
    StrNCopy(buffer + kOldSaltSize, passwd, sizeof(buffer) - 1 - kOldSaltSize);
    pwlen = kOldSaltSize + StrLen(passwd);
    if (pwlen >= kOldMessageBufSize)
	pwlen = kOldMessageBufSize - 1;
    MemSet(buffer + pwlen, kOldMessageBufSize - pwlen, 0);
    MD5(buffer, kOldMessageBufSize, digest);
    MemWipe(buffer, sizeof(buffer));
    return MemCmp(digest, hash->hash, kMD5HashSize) == 0;
}

static UPGRADE_SECTION 
Err Upgrade_UnpackOldRecord(Char *recPtr,
			    UnpackedKeyType *unpacked, 
			    OldCryptoKey recordKey) {
    void* plainBuf;
    Char* destPtr;
    Char* decryptBuf;
    PackedFieldType *pft;
    Int16 decryptSize;
    Int16 size = MemPtrSize(recPtr);
    Int16 i;
    plainBuf = MemPtrNew(size + 5 * sizeof(PackedFieldType) + 2);
    unpacked->plainText = plainBuf;
    unpacked->numFields = 0;
    
    /* Copy Name */
    pft = (PackedFieldType*) plainBuf;
    destPtr = (Char*) (pft + 1);
    while (*recPtr != 0 && size > 0) {
	*destPtr++ = *recPtr++;
	size--;
    }
    unpacked->fieldOffset[unpacked->numFields++] = 0;
    pft->len = destPtr - (Char*) (pft+1);
    pft->labelID = 0;
    pft->fontID = 0;
    pft = (PackedFieldType *) ((UInt16*) (pft+1) + ((pft->len+1) >> 1));
    recPtr++;  /* skip NUL */
    size--;

    decryptSize = size;
    decryptBuf = MemPtrNew(size);
    for (i = 0; i < size; i += 8) {
	des_ecb2_encrypt((void *) recPtr + i, (void*) decryptBuf + i, 
			 recordKey[0], recordKey[1], false);
    }

    /* Copy Account */
    recPtr = decryptBuf;
    destPtr = (Char*) (pft + 1);
    while (*recPtr != 0 && size > 0) {
	*destPtr++ = *recPtr++;
	size--;
    }
    if (destPtr > (Char*) (pft+1)) {
	unpacked->fieldOffset[unpacked->numFields++] = (void *)pft - plainBuf;
	pft->len = destPtr - (Char*) (pft+1);
	pft->labelID = 1;
	pft->fontID = 0;
	pft = (PackedFieldType *) ((UInt16*) (pft+1) + ((pft->len+1) >> 1));
    }
    recPtr++;
    size--;

    /* Copy Pasword */
    destPtr = (Char*) (pft + 1);
    while (*recPtr != 0 && size > 0) {
	*destPtr++ = *recPtr++;
	size--;
    }
    if (destPtr > (Char*) (pft+1)) {
	unpacked->fieldOffset[unpacked->numFields++] = (void *)pft - plainBuf;
	pft->len = destPtr - (Char*) (pft+1);
	pft->labelID = 2;
	pft->fontID = 0;
	pft = (PackedFieldType *) ((UInt16*) (pft+1) + ((pft->len+1) >> 1));
    }
    recPtr++;
    size--;

    /* Copy Notes */
    destPtr = (Char*) (pft + 1);
    while (*recPtr != 0 && size > 0) {
	*destPtr++ = *recPtr++;
	size--;
    }
    if (destPtr > (Char*) (pft+1)) {
	unpacked->fieldOffset[unpacked->numFields++] = (void *)pft - plainBuf;
	pft->len = destPtr - (Char*) (pft+1);
	pft->labelID = 255;
	pft->fontID = 0;
	pft = (PackedFieldType *) ((UInt16*) (pft+1) + ((pft->len+1) >> 1));
    }
    recPtr++;
    size--;


    /* Copy LastChangeTime */
    destPtr = (Char*) (pft + 1);
    if (size > 2 && (*recPtr != 0 || *(recPtr+1) != 0)) {
	*destPtr++ = *recPtr++;
	*destPtr++ = *recPtr++;
	size -= 2;
	unpacked->fieldOffset[unpacked->numFields++] = (void *)pft - plainBuf;
	pft->len = 2;
	pft->labelID = 3;
	pft->fontID = 0;
	pft = (PackedFieldType *) ((UInt16*) (pft+1) + 1);
    }
    pft->len = ENDMARKER;

    
    return 0;
}

static UPGRADE_SECTION 
Err Upgrade_ConvertRecords(DmOpenRef oldDB, char *passwd) {
    OldCryptoKey oldRecordKey;
    CryptoKey   *newRecordKey;
    SimpleUnpackedKeyType unpacked;
    MemHandle   recHand;
    void        *recPtr;
    UInt16      numRecs = DmNumRecords(oldDB);
    UInt16      idx;
    UInt16      newIdx;
    UInt8       keyMD5sum[kMD5HashSize];
    Err         err;
    UInt16      attr;

    newRecordKey = MemPtrNew(sizeof(CryptoKey));
    if (!newRecordKey)
	return memErrNotEnoughSpace;
    if (!PwHash_Check(newRecordKey, passwd))
	return appErrMisc;

    MD5((void *) passwd, StrLen(passwd), keyMD5sum);
    des_set_odd_parity((des_cblock*) keyMD5sum);
    des_set_key((des_cblock*) keyMD5sum, oldRecordKey[0]);
    des_set_odd_parity((des_cblock*) keyMD5sum + 1);
    des_set_key((des_cblock*) keyMD5sum + 1, oldRecordKey[1]);
    MemWipe(keyMD5sum, sizeof(keyMD5sum));

    err = 0;
    for (idx = 0; idx < numRecs; idx++) {
	err = DmRecordInfo(oldDB, idx, &attr, NULL, NULL);
	if (err)
	    break;
	if (attr & (dmRecAttrDelete | dmRecAttrSecret))
	    continue;

	if (!(recHand = DmQueryRecord(oldDB, idx))
	    || !(recPtr = MemHandleLock(recHand))) {
	    err = DmGetLastErr();
	    break;
	}
	Upgrade_UnpackOldRecord(recPtr, &unpacked.unpacked, oldRecordKey);
        MemHandleUnlock(recHand);
	unpacked.unpacked.category = attr & dmRecAttrCategoryMask;

	KeyDB_CreateNew(&newIdx);
	Record_SaveRecord(&unpacked.unpacked, newIdx, newRecordKey);
	MemWipe(unpacked.unpacked.plainText, 
		MemPtrSize(unpacked.unpacked.plainText));
	MemPtrFree(unpacked.unpacked.plainText);

        err = DmReleaseRecord(gKeyDB, newIdx, true);
	if (err)
	    break;
    }
    MemWipe(oldRecordKey, sizeof(oldRecordKey));
    MemWipe(newRecordKey, sizeof(newRecordKey));
    CryptoDeleteKey(newRecordKey);
    MemPtrFree(newRecordKey);
    return err;
}

static UPGRADE_SECTION 
Err Upgrade_ConvertDB(int oldVersion, char *passwd, Int16 cipher, Int16 iter) {
    LocalID oldDBID = gKeyDBID;
    LocalID oldAppInfoID, newAppInfoID;
    DmOpenRef oldDB = gKeyDB;
    UInt32 type;
    Err err;

    if ((err = DmCreateDatabase(gKeyDBCardNo, kKeyDBTempName,
				kKeyringCreatorID, kKeyDBTempType,
				false /* not resource */)))
	return err;

    gKeyDBID = DmFindDatabase(gKeyDBCardNo, kKeyDBTempName);
    if (!gKeyDBID) {
	gKeyDBID = oldDBID;
	return DmGetLastErr();
    }

    KeyDB_SetDBInfo(gKeyDBCardNo, gKeyDBID);
    gKeyDB = DmOpenDatabase(gKeyDBCardNo, gKeyDBID, dmModeReadWrite);
    if (!gKeyDB) {
	gKeyDB   = oldDB;
	gKeyDBID = oldDBID;
	return DmGetLastErr();
    }
	
    err = KeyDB_InitDB(passwd, cipher, iter);
    if (err)
	goto outErr;

    if (oldVersion > 0) {
	/* Copy categories */
	AppInfoType   *oldPtr;
	KrAppInfoType *newPtr;
	if ((err = DmDatabaseInfo(gKeyDBCardNo, oldDBID,
				  0, 0, 0, 0, 0, 0, 0,
				  &oldAppInfoID, 0, 0, 0)))
	    goto outErr;
	if (oldAppInfoID) {
	    oldPtr = MemLocalIDToLockedPtr(oldAppInfoID, gKeyDBCardNo);
	    if (!oldPtr) {
		err = DmGetLastErr();
		goto outErr;
	    }
	    if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
				      0, 0, 0, 0, 0, 0, 0,
				      &newAppInfoID, 0, 0, 0))) {
		MemPtrUnlock(oldPtr);
		goto outErr;
	    }
	    newPtr = MemLocalIDToLockedPtr(newAppInfoID, gKeyDBCardNo);
	    if (!newPtr) {
		err = DmGetLastErr();
		MemPtrUnlock(oldPtr);
		goto outErr;
	    }
	    DmWrite(newPtr, 0, oldPtr, sizeof(AppInfoType));
	    MemPtrUnlock(newPtr);
	    MemPtrUnlock(oldPtr);
	}
    }

    err = Upgrade_ConvertRecords(oldDB, passwd);
    if (err)
	goto outErr;

    /* Remove old database */
    if ((err = DmCloseDatabase(oldDB)))
	goto outErr;
    if ((err = DmDeleteDatabase(gKeyDBCardNo, oldDBID)))
	goto outErr;
    /* Rename new database, ignore errors. 
     * Old database was deleted, we do not want the new database to be
     * deleted, too.
     */
    type = kKeyDBType;
    err = DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			    kKeyDBName, 0, 0, 0, 0, 0, 0, 0, 0, &type, 0);
    return err;

 outErr:
    DmCloseDatabase(gKeyDB);
    DmDeleteDatabase(gKeyDBCardNo, gKeyDBID);
    gKeyDB = oldDB;
    gKeyDBID = oldDBID;
    return err;
}

/* Convert from a database version oldVersion to the new version. */
UPGRADE_SECTION Err UpgradeDB(UInt16 oldVersion)
{
    Err err;

    if (oldVersion < 5) {
	/* The old versions up to keyring-1.2.x are all similar, but
	 * differ in the way the password hash was stored 
	 */
	OldCheckHashType checkHash;
	Char            *passwd;
	UInt16           cipher, iter;

	/* Check if the necessary openssl libraries are installed */
	if (CheckGlib('CrDS', "DESLib.prc")
	    || CheckGlib('CrMD', "MDLib.prc"))
	    return appErrMisc;

	switch (oldVersion) {
	case 0:
	    /* This was the format up to 0.9.2.  It encrypts everything *
	     *  with the hash of the password, and stores the checking
	     *  hash in the AppInfo section. */
	    err = Upgrade_From0(&checkHash);
	    break;
	case 1:
	    /* This version kept the password in the SortInfo section. */
	    err = Upgrade_From1(&checkHash);
	    break;
	case 4:
	    /* This version kept the password in a hidden record */
	    err = Upgrade_From4(&checkHash);
	    break;
	default:
	    UpgradeDB_Failed(oldVersion);
	    return appErrMisc;
	}
	if (err == 0) {
	    if (FrmAlert(UpgradeAlert) != 0)
		return appCancelled;
	} else if (err == appErrMissingHash) {
	    /* Handle a database that's missing its SortInfo data, having been
	     * restored from a broken backup.
	     */
	    
	    if (FrmAlert(alertID_PasswordHashMissing) != 0)   /* 0 = "OK" */
		return appCancelled;
	} else {
	    return err;
	}

        for(;;){
	    passwd = SetPasswd_Ask(&cipher, &iter);
	    if (passwd == NULL)
		return appCancelled;
	    if (err == appErrMissingHash) {
		/* We cannot check for password; assume it was right */
		err = 0;
		break;
	    }
	    if (Upgrade_CheckPwHash(passwd, &checkHash))
		break;
	    else
                FrmAlert(WrongKeyAlert);
	}
	if (!err) {
	    FormPtr	frm, oldFrm;
	    oldFrm = FrmGetActiveForm();
	    frm = FrmInitForm(BusyEncryptForm);
	    FrmSetActiveForm(frm);
	    FrmDrawForm(frm);

	    err = Upgrade_ConvertDB(oldVersion, passwd, cipher, iter);

	    FrmEraseForm(frm);
	    FrmDeleteForm(frm);
	    if (oldFrm)
		FrmSetActiveForm(oldFrm);
	}
    } else {
	UpgradeDB_Failed(oldVersion);
	err = appErrMisc;
    }
    return err;
}

