/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 by Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2005 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

#define offsetof(str,fld) ((UInt16) &(((str *) NULL)->fld))

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


Err KeyDB_CreateAppInfo(void)
{
    LocalID      appInfoID;
    MemHandle    appInfoHandle;
    KrAppInfoPtr appInfoPtr;

    UInt16       appInfoSize;

#ifdef SUPPPORT_TEMPLATES
    MemHandle    templateHandle;
    UInt16       offset;
    UInt8        *templatePtr, *templateBlock;
    UInt8        numLabels;
    UInt8        numTemplates;
    UInt16       templateLength;

    templateHandle = DmGetResource('TMPL', 1000);
    templatePtr = templateBlock = MemHandleLock(templateHandle);

    numLabels = 0;
    numTemplates = 0;
    templateLength = 0;
    while (*templatePtr != 0) {
	int namlen = StrLen(templatePtr);
	templatePtr += namlen + 3;
	numLabels++;
    }
    templatePtr++;
    while (*templatePtr != 0) {
	int namlen = StrLen(templatePtr);
	int comps;
	templatePtr += namlen + 1;
	comps = *templatePtr;
	templatePtr += comps + 1;
	templateLength += namlen + 1 + comps + 1;
	numTemplates++;
    }
#endif

    appInfoSize = sizeof(KrAppInfoType);
#ifdef SUPPPORT_TEMPLATES
    appInfoSize += numLabels * sizeof(KrLabelType)
	+ templateLength;
#endif
    appInfoHandle = DmNewHandle(gKeyDB, appInfoSize);
    if (!appInfoHandle) {
#ifdef SUPPPORT_TEMPLATES
	MemHandleUnlock(templateHandle);
	DmReleaseResource(templateHandle);
#endif
	return DmGetLastErr();
    }
    
    appInfoID = MemHandleToLocalID(appInfoHandle);
    DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
		      0,0,0,0,
		      0,0,0,
		      &appInfoID, 0,0,0);
    appInfoPtr = MemLocalIDToLockedPtr(appInfoID, gKeyDBCardNo);

    /* Clear the app info block. */
    DmSet(appInfoPtr, 0, appInfoSize, 0);

    /* Initialize the categories. */
    CategoryInitialize(&appInfoPtr->categoryInfo, CategoryRsrc);
    
#ifdef SUPPPORT_TEMPLATES
    DmWrite(appInfoPtr, offsetof(KrAppInfoType, numberOfLabels), 
	    &numLabels, 1);
    DmWrite(appInfoPtr, offsetof(KrAppInfoType, numberOfTemplates),
	    &numTemplates, 1);

    /* Initialize default fields. */
    numLabels = 0;
    offset    = sizeof(KrAppInfoType);
    templatePtr = templateBlock;
    while (*templatePtr != 0) {
	int namlen = StrLen(templatePtr);
	if (namlen > 16)
	    namlen = 16;
	DmWrite(appInfoPtr, offset, templatePtr, namlen);
	offset += 16;
	templatePtr += namlen + 1;
	DmWrite(appInfoPtr, offset, templatePtr, 2);
	templatePtr += 2;
	offset += 2;
    }
    templatePtr++;
    /* Initialize the templates. */
    DmWrite(appInfoPtr, offset, templatePtr, templateLength);

    MemHandleUnlock(templateHandle);
    DmReleaseResource(templateHandle);
#endif

    MemPtrUnlock(appInfoPtr);
    return 0;
}


Err KeyDB_SetDBInfo(Int16 cardNo, LocalID id) 
{
    UInt16 version = kDatabaseVersion;
    UInt16 attr;

    DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, NULL, &attr, NULL, NULL,
		   NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    attr |= dmHdrAttrBackup;
    return DmSetDatabaseInfo(cardNo, id,
			     NULL, &attr, &version,
			     NULL, NULL, NULL, NULL,
			     NULL, NULL, NULL, NULL);
}

Err KeyDB_InitDB(char* newPasswd, Int16 cipher, Int16 iter)
{
    SaltHashType salthash;
    Err err;

    if ((err = KeyDB_CreateAppInfo()))
	return err;
    
    err = PwHash_Create(newPasswd, cipher, iter, &salthash, NULL);
    if (!err)
	PwHash_Store(newPasswd, &salthash);
    MemWipe(&salthash, sizeof(salthash));
    return err;
}


#define KeyDB_GetVersion(ver) \
    DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0, \
		   ver, 0, 0, 0, 0, 0, 0, 0, 0)

static Err KeyDB_CreateDB(void) {
    Err err;
    Char *newPasswd;
    UInt16 cipher, iter;

    newPasswd = SetPasswd_Ask(&cipher, &iter);
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

    err = KeyDB_SetDBInfo(gKeyDBCardNo, gKeyDBID);
    MemWipe(newPasswd, StrLen(newPasswd));
    MemPtrFree(newPasswd);
    if (err)
	goto outErr;

    gKeyDB = DmOpenDatabase(gKeyDBCardNo, gKeyDBID, dmModeReadWrite);
    if (!gKeyDB)
	goto outFindErr;

    err = KeyDB_InitDB(newPasswd, cipher, iter);
    if (err)
	goto outErr;
    return 0;

 outFindErr:
    err = DmGetLastErr();
    
 outErr:
    if (gKeyDB)
	DmCloseDatabase(gKeyDB);
    if (gKeyDBID)
	DmDeleteDatabase(gKeyDBCardNo, gKeyDBID);

    UI_ReportSysError2(ID_CreateDBAlert, err, __FUNCTION__);
    return err;
}


/*
 * Get everything going: either open an existing DB (converting if
 * necessary), or create a new one, or return an error.
 */
Err KeyDB_Init(void)
{
     Err    err;
     UInt16 ver;
    
     /* If the database doesn't already exist, then we require the user
      * to set their password. */
     err = KeyDB_OpenExistingDB();

     switch (err) {
     case errNone:
	 break;

     case dmErrReadOnly:
     case dmErrROMBased:
	 if (!Keyring_AcceptsReadOnly())
	     return appCancelled;

	 if ((err = KeyDB_OpenReadOnly()))
	     goto failDB;
	 break;
	 
     case dmErrCantFind:
	 if ((err = KeyDB_CreateDB()))
	     return err;           /* error already reported */
	 break;

     default:	 
	 goto failDB;
     }

     /* So, we opened a database OK.  Now, is it old, new, or
	just right? */
     if ((err = KeyDB_GetVersion(&ver))) {
	 UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	 goto closeDB;
     }
     if (ver < kDatabaseVersion) {
	 if (g_ReadOnly) {
	     FrmAlert(alertID_UpgradeReadOnly);
	     goto closeDB;
	 }

	 if ((err = UpgradeDB(ver))) {
	     if (err != appErrMisc && err != appCancelled)
		 UI_ReportSysError2(UpgradeFailedAlert, err, __FUNCTION__);
	     goto closeDB;
	 }
     } else if (ver > kDatabaseVersion) {
	 FrmAlert(TooNewAlert);
	 goto closeDB;
     }

     if (!g_ReadOnly) {
	 /* Sort Database just in case a backup program scrambled the
	  * record order. */
	 Keys_Sort();
     }

     /* Remember or clear the r/o state, so one doesn't need to reconfirm. */
     PrefSetAppPreferences(kKeyringCreatorID, prefID_ReadOnlyAccepted,
                           kAppVersion, 
			   g_ReadOnly ? &g_ReadOnly : NULL, 
			   g_ReadOnly ? sizeof(g_ReadOnly) : 0, true);
     return 0;

 failDB:
     UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
     return err;

 closeDB:
     DmCloseDatabase(gKeyDB);
     gKeyDB = 0;
     return err;
}

KrAppInfoPtr KeyDB_LockAppInfo(void) {
    LocalID appInfoID = 0;
    DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0, 0, 0,
		   0, 0, 0, 
		   &appInfoID, 0, 0, 0);
    ErrFatalDisplayIf(appInfoID == 0, "AppInfo destroyed");
    return MemLocalIDToLockedPtr(appInfoID, gKeyDBCardNo);
}

