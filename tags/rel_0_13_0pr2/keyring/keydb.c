/* -*- c-indentation-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: t; -*-
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
#include "sesskey.h"
#include "error.h"
#include "uiutil.h"
#include "auto.h"

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
 * We encrypt the records not with the master password itself, but
 * rather with a session key stored in record 0 of the database.  The
 * session key is just random noise.  The session key is stored
 * encrypted by the master password.
 *
 * We also need to be able to tell whether the user has entered the
 * right master password, since we want to give them an error message
 * rather than just display random garbage.  Therefore the MD5 hash of
 * the master password is also stored.  This goes into record #1.
 *
 * Rather than worrying about creating these records when they're
 * used, we create them with the database so we know they'll never be
 * used.  These records are marked secret, because that flag is not
 * otherwise used in this application.
 *
 * Once the session key is set, it is never changed throughout the
 * life of the database.  If the user changes their master password,
 * then we re-encrypt the session key with the new password and store
 * that as record 0.  This is (I think) as close to atomic as we can
 * get under PalmOS.  It would be a bad thing if e.g. the system
 * crashed while we were changing it, and the session key was lost. */


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
    SessKey_Store(newPasswd);
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
 * Create the reserved records that will contain the encrypted session
 * key and master password check-hash.  We don't populate them yet,
 * but creating them here means that later on we can just count on
 * them existing and being in the right place.
 *
 * gKeyDB is open and refers to an empty database when this is called.
 */
static Err KeyDB_CreateReservedRecords(void)
{
    Err err;
    Int16 i, idx;
    UInt16 attr;
    MemHandle recHandle;

    for (i = 0; i <= 1; i++) {
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
    
    if ((err = SessKey_Generate()))
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


Int16 Keys_IdxOffsetReserved(void)
{
    if (gPrefs.category == 0 || gPrefs.category == dmAllCategories) 
	return kNumHiddenRecs;
    else
	return 0;
}