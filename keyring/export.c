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

/* FIXME: MemoPad limits memos to 4kb.  We should use that too, and
 * make sure that we never write out more text than can be accepted. */

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "keydb.h"
#include "record.h"
#include "util.h"
#include "memutil.h"
#include "dbutil.h"
#include "export.h"

#define kMaxExport (16<<10)


static UInt32 const kMemoType = 'DATA', kApplType = 'appl';
static UInt32 const kMemoCreator = 'memo';


static void Export_Failure(void)
{
    FrmAlert(MemoDatabaseErrorAlert);
}


/* Convert a record to text form, and return a pointer to a
 * newly-allocated buffer containing it.  The caller should free the
 * buffer after use.  Returns 0 if unsuccessful. */
static UInt16 Export_BuildText(UnpackedKeyType *keyRecord,
			       void *memoRecord)
{
    UInt32	off;

    /* XXX: Ugh, ugly.  Try rewriting this more concisely. */

    off = 0;
    DB_WriteStringFromHandle(memoRecord, &off, keyRecord->nameHandle,
			     keyRecord->nameLen);
    if (keyRecord->acctHandle) {
	DB_WriteString(memoRecord, &off, "\nAccount: ");
	DB_WriteStringFromHandle(memoRecord, &off, keyRecord->acctHandle,
				 keyRecord->acctLen);
    }
    if (keyRecord->passwdHandle) {
	DB_WriteString(memoRecord, &off, "\nPassword: ");
	DB_WriteStringFromHandle(memoRecord, &off, keyRecord->passwdHandle,
				 keyRecord->passwdLen);
    }
    if (keyRecord->notesHandle) {
	DB_WriteString(memoRecord, &off, "\n\n");
	DB_WriteStringFromHandle(memoRecord, &off, keyRecord->notesHandle,
				 keyRecord->notesLen);
    }
    DB_WriteString(memoRecord, &off, "\n(Exported from GNU Keyring)");

    DmWrite(memoRecord, off, "", 1); /* write nul */
    off++;
    return (UInt16) off;
}


/* Write out a text buffer as a new memo. */
static void* Export_CreateMemo(DmOpenRef *dbp, Int16 *pidx, LocalID *memoDbID,
			       UInt16 *memoDbCard)
{    
    UInt32	recLen;
    Err		err;
    MemHandle	newHandle;
    void *     recPtr;

    if (!(*dbp = DmOpenDatabaseByTypeCreator(kMemoType, kMemoCreator, dmModeReadWrite)))
	goto failOut;

    err = DmOpenDatabaseInfo(*dbp, memoDbID, NULL, NULL, memoDbCard, NULL);
    if (err)
	goto failClose;

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
    
    DmCloseDatabase(dbp);
    return 1;
}


/* Jump to the just-created memo. */
static int Export_JumpToMemo(LocalID memoDbID, UInt16 memoDbCard, Int16 idx) {
    UInt16		appCard = 0;
    Err			err;
    LocalID		appID;
    GoToParamsPtr	params;
    UInt16		cmd = 0;
    DmSearchStateType	state;

    /* Work out the database ID for the MemoPad application and data. */
    err = DmGetNextDatabaseByTypeCreator(true, &state, kApplType,
					 kMemoCreator, true, &appCard,
					 &appID);
    if (err) {
	FrmAlert(CouldntLaunchMemoAlert);
	return 0;
    }
    
    /* Construct a GoToParameters pointing to this record. */
    if (!(params = MemPtrNew(sizeof *params))) {
	FrmAlert(OutOfMemoryAlert);
	return 0;
    }
    MemSet(params, sizeof *params, 0);
    params->dbCardNo = memoDbCard;
    params->dbID = memoDbID;
    params->recordNum = idx;
        
    /* Give ownership of the PBP to the operating system, so that it
     * is not freed when we exit.  */
    err = MemPtrSetOwner(params, 0);
    if (err) {
	FrmAlert(CouldntLaunchMemoAlert);
	return 0;
    }

    cmd = sysAppLaunchCmdGoTo;
    err = SysUIAppSwitch(appCard, appID, cmd, params);

    return 1;
}


/* Export the current key to a MemoPad record. */
void ExportKey(UnpackedKeyType *keyRecord)
{
    void	*memoRecord;
    Int16	idx;
    Int16	size;
    DmOpenRef	dbp;
    LocalID	memoDbID;
    UInt16	memoDbCard;

    if (!(memoRecord = Export_CreateMemo(&dbp, &idx, &memoDbID, &memoDbCard))) {
	Export_Failure();
    } else if (!(size = Export_BuildText(keyRecord, memoRecord))) {
	Export_Failure();
    } else if (!Export_Finish(dbp, idx, size, memoRecord)) {
	Export_Failure();
    } else {
	Export_JumpToMemo(memoDbID, memoDbCard, idx);
    }
}
