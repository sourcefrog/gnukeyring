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

#include <PalmOS.h>

#include "keyring.h"
#include "keydb.h"
#include "crypto.h"
#include "pwhash.h"
#include "resource.h"
#include "keydb.h"
#include "uiutil.h"
#include "auto.h"

/*
 * Store the checking-hash of a password into record[kMasterHashRec].
 */
Err PwHash_Store(Char *newPasswd)
{
    Err			err;
    Char		digest[kMD5HashSize];
    MemHandle		recHandle;
    void		*recPtr;
    Int16		idx;

    err = EncDigestMD5(newPasswd, StrLen(newPasswd), digest);
    if (err) {
	App_ReportSysError(CryptoErrorAlert, err);
	return err;
    }

    idx = kMasterHashRec;
    recHandle = DmNewRecord(gKeyDB, &idx, kMD5HashSize);
    if (!recHandle) {
	App_ReportSysError(ID_KeyDatabaseAlert, DmGetLastErr());
	return err;
    }

    recPtr = MemHandleLock(recHandle);

    DmWrite(recPtr, 0, digest, kMD5HashSize);

    MemHandleUnlock(recHandle);

    return 0;
}


/*
 * Check whether GUESS is the correct password for the database.
 */
Boolean PwHash_Check(Char *guess)
{
    Char		digest[kMD5HashSize];
    MemHandle		recHandle;
    Char		*recPtr;
    Boolean		result;
    Err			err;

    /* Compute the hash of the entered password. */
    err = EncDigestMD5(guess, StrLen(guess), digest);
    if (err) {
	App_ReportSysError(CryptoErrorAlert, err);
	return false;
    }

    /* Retrieve the hash record. */
    recHandle = DmQueryRecord(gKeyDB, kMasterHashRec);
    if (!recHandle) {
	App_ReportSysError(ID_KeyDatabaseAlert, err);
	return false;
    }
    recPtr = MemHandleLock(recHandle);

    result = !MemCmp(digest, recPtr, kMD5HashSize);
    MemHandleUnlock(recHandle);

    return result;
}


