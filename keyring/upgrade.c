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

/*
 * TODO: In the future, when converting the database, write out to a
 * new database so that if something goes wrong we won't be lost.
 *
 * TODO: Upgrade to v3 from v1.
 */

static void UpgradeDB_Failed(int oldVersion)
{
    char oldVer[8];
    StrIToA(oldVer, oldVersion);
    FrmCustomAlert(CantUpgradeAlert, oldVer, "", "");
}



static Err Upgrade_MoveToHash(LocalID id)
{
     UInt16       pos = 0;
     UInt8        *hashPtr;
     UInt8        *recPtr;
     MemHandle    recHandle;
     UInt16       attr;
     Err err;
     
     /* Detach this chunk from the SortInfo or AppInfo, and attach it as
      * record 0. */
     hashPtr = MemLocalIDToLockedPtr(id, gKeyDBCardNo);
     if (!hashPtr) {
          FrmCustomAlert(UpgradeFailedAlert, "couldn't lock hash info", "", "");
     }

     recHandle = DmNewRecord(gKeyDB, &pos, sizeof (CheckHashType));
     if (!recHandle) {
          err = DmGetLastErr();
          goto outErr;
     }
     
     recPtr = MemHandleLock(recHandle);
     if ((err = DmWrite(recPtr, 0, hashPtr, sizeof (CheckHashType)))) 
          goto outErr;

     if ((err = DmReleaseRecord(gKeyDB, pos, true)))
          goto outErr;

     attr = dmRecAttrSecret | dmRecAttrDirty;
     if ((err = DmSetRecordInfo(gKeyDB, pos, &attr, NULL)))
          goto outErr;

     MemPtrUnlock(recPtr);
     MemPtrUnlock(hashPtr);
     return 0;

 outErr:
     UI_ReportSysError2(UpgradeFailedAlert, err, __FUNCTION__);
     return err;
}



static Err Upgrade_From0(void)
{
    /* Move the AppInfo block to the SortInfo block */
    LocalID             appInfoID;
    Err			err;

    if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0,
			      0, 0, 0, 0,
			      &appInfoID, 0,
			      0, 0)))
	return err;

    if ((err = Upgrade_MoveToHash(appInfoID)))
         return err;

    appInfoID = 0;
    if ((err = DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0,
			      0, 0, 0, 0,
			      &appInfoID, 0,
			      0, 0)))
	return err;
    
    FrmAlert(ID_CategoriesMissing);
    if ((err = KeyDB_CreateCategories()))
	return err;

    return 0;
}


/* Handle a database that's missing its SortInfo data, having been
 * restored from a broken backup.  We temporarily allow this access,
 * and explain that the user should reset their password.  Return true
 * if access should be allowed, false to abort. 
 */
Err Upgrade_HandleMissingHash(void)
{
     Char       *newPasswd;

     if (FrmAlert(alertID_PasswordHashMissing) != 0)   /* 0 = "OK" */
          return appCancelled;

     newPasswd = SetPasswd_Ask();
     if (newPasswd == NULL)
          return appCancelled;

     KeyDB_CreateReservedRecords();
     PwHash_Store(newPasswd);

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
static Err Upgrade_From1(void)
{
     LocalID      sortInfoID, appInfoID;
     Err	  err;

     if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
                               0, 0, 0, 0, 0, 0, 0,
                               &appInfoID, &sortInfoID,
                               0, 0))) {
          UI_ReportSysError2(UpgradeFailedAlert, err, __FUNCTION__);
          goto outErr;
     }

     if (sortInfoID == 0) {
          /* TODO: Go through the checking-hash recovery procedure. */
          return Upgrade_HandleMissingHash();
     }

     if (appInfoID == 0) {
          /* Shouldn't happen, but it's possible that there's no
           * category data there. */
          FrmAlert(ID_CategoriesMissing);
          if ((err = KeyDB_CreateCategories()))
               goto outErr;
     }

     if ((err = Upgrade_MoveToHash(sortInfoID)))
          return err;

     /* Finally remove it from the SortInfo field. */
     sortInfoID = 0;
     if ((err = DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
                                  0, 0, 0, 0, 0, 0, 0,
                                  0, &sortInfoID,
                                  0, 0)))
          goto outErr;

     return 0;

 outErr:
     UI_ReportSysError2(UpgradeFailedAlert, err, __FUNCTION__);
     return err;
}



/* Convert from a database version oldVersion to the new version. */
Err UpgradeDB(UInt16 oldVersion)
{
    Err err;

    if (oldVersion == 0) {
	/* This was the format up to 0.9.2.  It encrypts everything *
	 *  with the hash of the password, and stores the checking
	 *  hash in the AppInfo section. */
	if ((err = Upgrade_From0())) {
             if (err != appErrMisc)
                  UI_ReportSysError2(UpgradeFailedAlert, err, __FUNCTION__);
             return err;
	}
    } else if (oldVersion == 1) {
        /* Kept a password has in the AppInfo section. */
        if ((err = Upgrade_From1())) 
            return err;
    } else {
	UpgradeDB_Failed(oldVersion);
	return appErrMisc;
    }

    KeyDB_SetVersion();
    return 0;
}

