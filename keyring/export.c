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
#include "keydb.h"
#include "util.h"
#include "memutil.h"

#define kMaxExport (16<<10)


static void Export_Failure()
{
    FrmAlert(MemoDatabaseErrorAlert);
}


/* Convert a record to text form, and return a pointer to a
 * newly-allocated buffer containing it.  The caller should free the
 * buffer after use.  Returns 0 if unsuccessful. */
UInt16 Export_BuildText(UnpackedKeyType *keyRecord,
		     void *memoRecord)
{
    UInt32	off;

    off = 0;
    DB_WriteStringFromHandle(memoRecord, &off, keyRecord->nameHandle,
			     keyRecord->nameLen + 1);
    return (UInt16) off;
}


/* Write out a text buffer as a new memo. */
static void* Export_CreateMemo(DmOpenRef *dbp, Int16 *pidx)
{    
    UInt32	recLen;
    Err		err;
    MemHandle	newHandle;
    void *     recPtr;

    if (!(*dbp = DmOpenDatabaseByTypeCreator('DATA', 'memo', dmModeReadWrite)))
	goto failOut;

    recLen = kMaxExport;
    *pidx = dmMaxRecordIndex;
    newHandle = DmNewRecord(*dbp, pidx, recLen);
    if (!newHandle) 
	goto failClose;

    recPtr = MemHandleLock(newHandle);
    if (!recPtr) 
	goto failDelete;
	
    return recPtr;
    

 failDelete:
    DmDeleteRecord(*dbp, *pidx);    
    
 failClose:
    DmCloseDatabase(*dbp);

 failOut:
    return NULL;
}



static Int16 Export_Finish(DmOpenRef dbp, Int16 idx, Int16 size, void *recPtr)
{
    Boolean	dirty = true;
    
    MemPtrUnlock(recPtr);
    DmReleaseRecord(dbp, idx, dirty);

    if (!(DmResizeRecord(dbp, idx, size))) {	
	return 0;
    }
    
 outCloseDb:
    DmCloseDatabase(dbp);
    return 1;
}



/* Export the current key to a MemoPad record. */
void ExportKey(UnpackedKeyType *keyRecord)
{
    void	*memoRecord;
    Int16	idx;
    Int16	size;
    DmOpenRef dbp;

    if (!(memoRecord = Export_CreateMemo(&dbp, &idx))) {
	Export_Failure();
    } else if (!(size = Export_BuildText(keyRecord, memoRecord))) {
	Export_Failure();
    } else if (!Export_Finish(dbp, idx, size, memoRecord)) {
	Export_Failure();
    }
}
