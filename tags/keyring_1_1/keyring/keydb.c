/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 by Martin Pool <mbp@users.sourceforge.net>
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

#include "includes.h"


Int16 gKeyDBCardNo;
LocalID gKeyDBID;

// Reference to the keys database
DmOpenRef       gKeyDB;

/*
 * True if the database can only be opened read-only; if e.g. the database is
 * stored in ROM.
 */
Boolean g_ReadOnly;


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
 */

/*
 * Either check that the user's already said a read-only database is
 * OK, or ask them.
 */
static Boolean Keyring_AcceptsReadOnly(void)
{
     Boolean accepted = false;
     Int16 size = sizeof accepted;
     Int16 ret;

     ret = PrefGetAppPreferences(kKeyringCreatorID,
                                 prefID_ReadOnlyAccepted,
                                 &accepted, &size,
                                 true);

     if (((ret == noPreferenceFound)
          || (size != sizeof accepted)
          || !accepted)) {
	 if (FrmAlert(alertID_OfferReadOnly) == 0)
	     accepted = true;
     }
     return accepted;
}



/*
 * Try to open an existing key database.
 * 
 * Will return an error if the database does not exist, in which case
 * you can try to create a new one.  
 */
static Err KeyDB_OpenExistingDB(void) {
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

     g_ReadOnly = false;

     return 0;
}


static Err KeyDB_OpenReadOnly(void)
{
     Err err;
    
     // TODO: Give people the option to name the database, or to create
     // it on different cards?
     gKeyDB = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
                                          dmModeReadOnly);
     if (!gKeyDB)
          return DmGetLastErr();

     if ((err = DmOpenDatabaseInfo(gKeyDB, &gKeyDBID, NULL, NULL,
                                   &gKeyDBCardNo, NULL)))
          return err;

     g_ReadOnly = true;

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


Err KeyDB_SetVersion(void) 
{
    UInt16 version = kDatabaseVersion;
    return DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			     NULL, NULL,
			     &version,
			     NULL, NULL, NULL, NULL,
			     NULL, NULL, NULL, NULL);
}


/* Set the backup bit.  It seems that without this the Windows desktop
 * software doesn't make the backup properly */
static Err KeyDB_MarkForBackup(void) {
    UInt16 attr;
    
    /* TODO: Here or elsewhere set the database version! */
    
    DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL, &attr, NULL, NULL,
		   NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    attr |= dmHdrAttrBackup;
    DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL, &attr, NULL, NULL,
		      NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    return 0;
}


static Err KeyDB_GetVersion(UInt16 *ver) {
    return DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0,
			  ver,
			  0, 0, 0, 0,
			  0, 0, 0, 0);
}


static Err KeyDB_CreateDB(void) {
    Err err;
    Char *newPasswd;

    newPasswd = SetPasswd_Ask();
    if (newPasswd == NULL)
	return appCancelled;

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
    
    PwHash_Store(newPasswd);
    MemSet(newPasswd, StrLen(newPasswd), 0);
    MemPtrFree(newPasswd);

    if ((err = KeyDB_MarkForBackup()))
	goto outErr;

    return 0;
    
 outFindErr:
    err = DmGetLastErr();
    
 outErr:
    UI_ReportSysError2(ID_CreateDBAlert, err, __FUNCTION__);
    return err;
}



static Err KeyDB_InitReadOnly(void)
{
     Err err;
     Int16 ver;
     
     if (!Keyring_AcceptsReadOnly())
          return appCancelled;

     if ((err = KeyDB_OpenReadOnly()))
          return err;
          
     if ((err = KeyDB_GetVersion(&ver)))
          return err;
          
     if (ver > kDatabaseVersion) {
	 FrmAlert(TooNewAlert);
	 return appCancelled;
     } else if (ver != kDatabaseVersion) {
	 FrmAlert(alertID_UpgradeReadOnly);
	 return appCancelled;
     }

     return 0;
}

/* Current database version may have problems finding
 * the hidden records containing hash if some backup
 * program shuffled it around.  
 */
static Err KeyDB_CheckHiddenRecord(void) {
    UInt16 len = DmNumRecords(gKeyDB);
    UInt16 i;
    UInt16 recAttr;

    if (len > 0
	&& DmRecordInfo(gKeyDB, 0, &recAttr, NULL, NULL) == errNone
	&& (recAttr & dmRecAttrSecret)) {
	/* Hidden record is okay */
	return errNone;
    }

    for (i = 0; i < len; i++) {
	if (DmRecordInfo(gKeyDB, i, &recAttr, NULL, NULL) == errNone
	    && (recAttr & dmRecAttrSecret)) {
	    /* We found the hash record. Move it to right position. */
	    DmMoveRecord(gKeyDB, i, 0);
	    return errNone;
	}
    }
    
    /* The hidden record is missing.  Ask for password and restore it.
     */
    return Upgrade_HandleMissingHash();
}

/*
 * Get everything going: either open an existing DB (converting if
 * necessary), or create a new one, or return an error.
 */
Err KeyDB_Init(void)
{
     Err                err;
     UInt16     ver;
    
     /* If the database doesn't already exist, then we require the user
      * to set their password. */
     err = KeyDB_OpenExistingDB();
    
     /* TODO: Check for dmErrReadOnly, dmErrROMBased and offer to open
      * the database read only.  If so, and the version is old, then
      * complain that we can't upgrade it. */

     if (err == dmErrReadOnly || err == dmErrROMBased) {
          if ((err = KeyDB_InitReadOnly())) {
               if (err == appCancelled)
                    return err;
               else
                    goto failDB;
          }
     } else if (err == dmErrCantFind && (err = KeyDB_CreateDB())) {
          return err;           /* error already reported */
     } else if (err) {
          goto failDB;
     }

     /* So, we opened a database OK.  Now, is it old, new, or
	just right? */
     if ((err = KeyDB_GetVersion(&ver)))
	 goto failDB;
     if (ver < kDatabaseVersion) {
	 if (g_ReadOnly) {
	     FrmAlert(alertID_UpgradeReadOnly);
	     return appCancelled;
	 }

	 if (FrmAlert(UpgradeAlert) != 0)
	     return appCancelled;

	 if ((err = UpgradeDB(ver)))
	     return err;
	     
	 /* We always mark the database here, because we may
	  * have converted from an old version of keyring that
	  * didn't do that. */
	 if ((err = KeyDB_MarkForBackup()))
	     goto failDB;
     } else if (ver > kDatabaseVersion) {
	 FrmAlert(TooNewAlert);
	 return appCancelled;
     } else {
	 if ((err = KeyDB_CheckHiddenRecord()))
	     return err;
     }

     /* Remember the r/o state, so one doesn't need to reconfirm. */
     PrefSetAppPreferences(kKeyringCreatorID, prefID_ReadOnlyAccepted,
                           kAppVersion, 
			   g_ReadOnly ? &g_ReadOnly : NULL, 
			   g_ReadOnly ? sizeof(g_ReadOnly) : 0, true);
     return 0;

 failDB:
     UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
     return err;
}
