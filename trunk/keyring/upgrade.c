/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 *
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 2000 Martin Pool <mbp@humbug.org.au>
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

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "memutil.h"
#include "keydb.h"
#include "crypto.h"
#include "upgrade.h"
#include "error.h"
#include "resource.h"


static void UpgradeDB_Failed(int oldVersion) {
    char oldVer[8];
    StrIToA(oldVer, oldVersion);
    FrmCustomAlert(CantUpgradeAlert, oldVer, "", "");
}


static Err Upgrade_From0(void) {
    /* Move the AppInfo block to the SortInfo block */
    LocalID             appInfoID, sortInfoID;
    Err			err;

    if ((err = DmDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0,
			      0, 0, 0, 0,
			      &appInfoID, &sortInfoID,
			      0, 0)))
	return err;

    if (sortInfoID != 0)
	return appErrMisc;

    sortInfoID = appInfoID;
    appInfoID = 0;

    if ((err = DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			      0, 0, 0,
			      0, 0, 0, 0,
			      &appInfoID, &sortInfoID,
			      0, 0)))
	return err;
    

    if ((err = KeyDB_CreateCategories()))
	return err;

    return 0;
}


/* Convert from a database version oldVersion to the new version. */
Err UpgradeDB(UInt16 oldVersion) {
    Err err;

    if (oldVersion == 0) {
	/* This was the format up to 0.9.2.  It encrypts everything
	 * with the hash of the password, and stores the encrypted
	 * session key in the AppInfo section. */
	if ((err = Upgrade_From0())) {
	    App_ReportSysError(UpgradeFailedAlert, err);
	    return err;
	}
    } else {
	UpgradeDB_Failed(oldVersion);
	return appErrMisc;
    }

    KeyDB_SetVersion();
    return 0;
}

