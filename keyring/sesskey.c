/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; -*-
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


/*
 * Manages session keys stored in hidden records at the start of the
 * database.
 */

/*
 * TODO: Generate a genuine random key, and save it encrypted by the
 * user's password.
 */

#include <PalmOS.h>

#include "keyring.h"
#include "memutil.h"
#include "crypto.h"
#include "resource.h"
#include "snib.h"
#include "auto.h"
#include "uiutil.h"
#include "sesskey.h"
#include "keydb.h"


/* Make up a new session key.  This is called only when creating a new
 * database -- calling it any other time will make the database
 * unreadable.  It's left in memory in the snib database, and can
 * later be encrypted and written out using SessKey_Store.  */
Err SessKey_Generate(void)
{
    UInt8       tmpKey[kDES3KeySize];
    Int16       i;

    for (i = 0; i < kDES3KeySize; i++)
        tmpKey[i] = (UInt8) SysRandom(0);
    
    Snib_SetSessKey(tmpKey);

    return 0;
}


/*
 * Load the session key from the main database, decrypt it, and store it in
 * the working database.
 */
Err SessKey_Load(Char *UNUSED(passwd))
{
    MemHandle recHandle;
    UInt8               *ptr;
    Err                 err;

    ErrFatalDisplayIf(!g_Snib, __FUNCTION__ ": no snib");

    recHandle = DmQueryRecord(gKeyDB, kSessionKeyRec);
    if (!recHandle) {
	err = DmGetLastErr();
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return err;
    }
    
    ptr = MemHandleLock(recHandle);
    Snib_SetSessKey(ptr);
    MemHandleUnlock(recHandle);
#if 0
    Snib_SetSessKey(noKey);
    err = 0;
#endif

    return err;
}


/*
 * Store SESSKEY encrypted by PASSWD into the reserved database
 * record.  
 */
Err SessKey_Store(Char *UNUSED(passwd))
{
    MemHandle recHandle;
    Err err;
    void *recPtr;
    
    ErrFatalDisplayIf(!g_Snib, __FUNCTION__ ": no snib");

    recHandle = DmResizeRecord(gKeyDB, kSessionKeyRec,
			       kDES3KeySize);
    if (!recHandle) {
	err = DmGetLastErr();
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return err;
    }

    recPtr = MemHandleLock(recHandle);

    DmWrite(recPtr, 0, g_Snib->sessKey, kDES3KeySize);

    MemHandleUnlock(recHandle);

    DmReleaseRecord(gKeyDB, kSessionKeyRec, true);

    return 0;
}

