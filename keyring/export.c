/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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
 * Export to Memo Pad function.
 *
 * Memo Pad records are limited to 4kB.  Since all our fields have
 * limits than sum to less than that we should always be OK.
 */

/*
 * FIXME: - Selecting a record to export to memo results in
 * "...possible memory leak...". The only time in my limited Palm
 * programming I ran into this was because all forms weren't closed
 * before exiting my app.  I'm not sure this is really a problem, as
 * memory should be given back by the fact Keyring has exited.  -- Dell
 *
 * TODO: Export using localized field headings, or perhaps don't
 * export the headings at all.
 */

#include "includes.h"

/*
 * Maximum length of record supported by the Memo Pad application
 */
#define kMaxExport (4<<10)

/*
 * Database constants to access the built-in Memo Pad.
 */
#define kMemoType 'DATA'
#define kApplType 'appl'
#define kMemoCreator 'memo'


static void Export_Failure(void)
{
    FrmAlert(MemoDatabaseErrorAlert);
}


/*
 * Write the exported form of an unpacked record into a pre-allocated
 * space in a memo record.  Returns the number of bytes written, which
 * will be the new length of the memo record.
 */
static UInt16 Export_BuildText(UnpackedKeyType *keyRecord,
			       void *memoRecord)
{
    UInt32	off;

    /* XXX: Ugh, ugly.  Try rewriting this more concisely. */

    off = 0;

    /* NB it's OK to call this with a null handle. */
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

    DmWrite(memoRecord, off, "", 1); /* write nul */
    off++;
    return (UInt16) off;
}


/*
 * Create a new memo to hold an exported record, and return a locked pointer
 * thereto.
 */
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



/*
 * Finish off the memo record: resize, unlock, and commit.
 */
static Int16 Export_Finish(DmOpenRef dbp, Int16 idx, Int16 size, void *recPtr)
{
    Boolean	dirty = true;
    
    MemPtrUnlock(recPtr);
    DmReleaseRecord(dbp, idx, dirty);

    if (!(DmResizeRecord(dbp, idx, size))) {
         /* XXX: Perhaps we should do this before releasing the
          * record?  I don't think it matters. */
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
     * is not freed when we exit.
     *
     * Who does free it in this case?  Are we sure it won't leak? */
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
