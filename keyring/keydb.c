/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Tightly Bound -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@humbug.org.au>
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
#include "pwhash.h"
#include "error.h"
#include "uiutil.h"
#include "auto.h"
#include "reencrypt.h"

Int16 gKeyDBCardNo;
LocalID gKeyDBID;

// Reference to the keys database
DmOpenRef       gKeyDB;


/* ======================================================================
 * Key database
 *
 * All the keys are kept in a single PalmOS database.  Each record
 * begins with an unencrypted name, which is followed by a
 * 3DES-encrypted block containing all the other fields.
 *
 * We encrypt all the records with a key directly derived from the MD5
 * hash of the master password.  This gives a 128 bit hash.  We split
 * this into two halves of 64 bits, and use them as DES encryption
 * keys K1 and K2.  (DES ignores a parity bit from each byte, so there
 * are actually only 56 unknown bits in each key.)
 *
 * As suggested in Schneier's ACv2, each block of the output is
 * encrypted as ENC(K1,DEC(K2,ENC(K1))).  Since we expect the records
 * to be relatively short, we don't worry about chaining blocks at the
 * moment: each is independently encrypted.
 *
 * We also need to be able to tell whether the user has entered the
 * right master password, since we want to give them an error message
 * rather than just display random garbage.  Therefore a salted hash
 * of the master password is also stored.  This goes into record #0.
 *
 * Rather than worrying about creating the reserved record when it's
 * used, we create them with the database so we know they'll never be
 * used.  These records are marked secret, because that flag is not
 * otherwise used in this application.
 *
 * When the user changes their password, we have to walk through the
 * database, decrypt each record with the old key, and re-encrypt with
 * the new key.
 *
 * NOTE: This scheme is not implemented in the current codebase,
 * because 0.13 up to dev3 digressed towards using an
 * independently-generated session key.  But it will be correct for
 * the final 0.13 release, and is almost correct for previous versions
 * except that the data was stored in AppInfo or SortInfo rather than
 * in record 0. */

/*
 * Set the master password for the database.  This is called after the
 * user has entered a new password and it has been properly checked,
 * so all it has to do is the database updates.  This routine is also
 * called when we're setting the initial master password for a newly
 * created database.
 *
 * This routine must do two things: re-encrypt the session key and
 * store it back, and store a check hash of the new password.
 */
void KeyDB_SetPasswd(Char *newPasswd)
{
     PwHash_Store(newPasswd);
     KeyDB_Reencrypt(newPasswd);
     Unlock_PrimeTimer();
}


/*
 * Try to open an existing key database.
 * 
 * Will return an error if the database does not exist, in which case
 * you can try to create a new one.  
 */
Err KeyDB_OpenExistingDB(void) {
    Err err;
    
    // TODO: Give people the option to name the database, or to create
    // it on different cards?
    gKeyDB = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
					 dmModeReadWrite);
    if (!gKeyDB)
	return DmGetLastErr();

    if ((err = DmOpenDatabaseInfo(gKeyDB, &gKeyDBID, NULL, NULL,
				  &gKeyDBCardNo, NULL)))
	return err;

    return 0;
}


/*
 * Create the reserved records that will contain the master password
 * check-hash.  We don't populate the record yet, but creating it here
 * means that later on we can just count on these records existing and
 * being in the right place.
 *
 * gKeyDB is open and refers to an empty database when this is called.
 *
 * At the moment we use only a single reserved record, but this
 * function can handle several.
 */
Err KeyDB_CreateReservedRecords(void)
{
    Err err;
    Int16 i, idx;
    UInt16 attr;
    MemHandle recHandle;

    for (i = 0; i < kNumHiddenRecs; i++) {
	idx = i;
	recHandle = DmNewRecord(gKeyDB, &idx, 1);
	if (!recHandle) {
	    err = DmGetLastErr();
	    goto outErr;
	}
	ErrNonFatalDisplayIf(idx != i, __FUNCTION__ " inserted into wrong place");

	if ((err = DmReleaseRecord(gKeyDB, idx, true)))
	    goto outErr;

	attr = dmRecAttrSecret | dmRecAttrDirty;
	if ((err = DmSetRecordInfo(gKeyDB, idx, &attr, NULL)))
	    goto outErr;
    }

    return 0;

 outErr:
    UI_ReportSysError2(ID_CreateDBAlert, err, __FUNCTION__);
    return err;
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
	goto outErr;

    gKeyDBID = DmFindDatabase(gKeyDBCardNo, kKeyDBName);
    if (!gKeyDBID)
	goto outFindErr;

    if ((err = KeyDB_SetVersion()))
	goto outErr;

    gKeyDB = DmOpenDatabase(gKeyDBCardNo, gKeyDBID, dmModeReadWrite);
    if (!gKeyDB)
	goto outFindErr;

    if ((err = KeyDB_CreateReservedRecords()))
	return err;
    
    if ((err = KeyDB_CreateCategories()))
	goto outErr;
    
    if (!SetPasswd_Run())
	return appCancelled;

    if ((err = KeyDB_MarkForBackup()))
	goto outErr;

    return 0;
    
 outFindErr:
    err = DmGetLastErr();
    
 outErr:
    UI_ReportSysError2(ID_CreateDBAlert, err, __FUNCTION__);
    return err;
}


/* Set the backup bit.  It seems that without this the Windows desktop
 * software doesn't make the backup properly */
Err KeyDB_MarkForBackup(void) {
    UInt16 attr;
    
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


Int16 Keys_IdxOffsetReserved(void)
{
    if (gPrefs.category == 0 || gPrefs.category == dmAllCategories) 
	return kNumHiddenRecs;
    else
	return 0;
}
