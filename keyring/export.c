/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 2000 Martin Pool
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

#include "resource.h"
#include "keyring.h"
#include "keyedit.h"
#include "callback.h"
#include "keydb.h"
#include "uiutil.h"
#include "util.h"
#include "generate.h"


static void ExportKey_Failure()
{
    FrmAlert(MemoDatabaseErrorAlert);
}


/* Export the current key to a MemoPad record. */
void ExportKey(UnpackedKeyType UNUSED(unpacked))
{
    DmOpenRef	dbp;
    Int16		idx;
    UInt32	recLen;
    Char const	*result = "Hallo!";
    Err		err;
    MemHandle	newHandle;
    void *     recPtr;
    Boolean	dirty = true;
    
    dbp = DmOpenDatabaseByTypeCreator('DATA', 'memo', dmModeReadWrite);
    if (!dbp) {
	ExportKey_Failure();
	return;
    }

    recLen = StrLen(result) + 1;

    idx = dmMaxRecordIndex;
    newHandle = DmNewRecord(dbp, &idx, recLen);
    if (!newHandle) {
	ExportKey_Failure();
	goto outCloseDb;
    }

    recPtr = MemHandleLock(newHandle);

    err = DmWrite(recPtr, 0, result, recLen);
    if (err) {
	ExportKey_Failure();
	/* but we just continue on and release it anyhow. */
	/* TODO: perhaps we should delete the record? */
    }
    MemPtrUnlock(recPtr);

    DmReleaseRecord(dbp, idx, dirty);

 outCloseDb:
    DmCloseDatabase(dbp);
}
