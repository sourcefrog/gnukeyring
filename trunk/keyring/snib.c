/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@humbug.org.au>
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
#include "memutil.h"
#include "crypto.h"
#include "resource.h"
#include "snib.h"
#include "auto.h"
#include "uiutil.h"

/*
 * The snib database holds working values which have to persist even
 * when switching to and from the Keyring application.  At the moment
 * this is just the expiry time, and the master password hash, which
 * is used as the encryption key for the records.
 *
 * We want to make fairly sure that this data cannot be stolen off the
 * handheld, so we destroy it on timeout.  At the moment that's only
 * when the timer expires, but eventually we should have a timer to
 * check it.
 *
 * FIXME: if the Keyring database is restored from backup, then the
 * application can be confused by a mismatched snib.  Therefore
 * ideally there would be some kind of cross-checking between them.
 */



#define k_SnibDBName "Keys-Gtkr-Temp"
#define k_SnibFtrId 'Sn'
#define k_SnibVersion 2

/*
 * We store the unlocked session key in a temporary database
 * not marked for backup.
 */
Err Snib_Init(void)
{
#ifndef NO_DELETE_OLD_KEY
    {
	 Int16   cardNo = 0;
	 LocalID dbID;
	 /* Remove old key Database */
	 dbID = DmFindDatabase(cardNo, k_SnibDBName);
	 if (dbID)
	      DmDeleteDatabase(cardNo, dbID);
    }
#endif
    return errNone;
}


/*
 * Release all records and close the database, we're leaving Keyring
 * (but may be coming back.)
 */
void Snib_Close(void)
{
}


/*
 * Reset the expiry time to zero, and also destroy the session key.
 * This method is called under special startup codes.  It must be in
 * the main code segment and must not use global variables.
 * It shouldn't do any time consuming things.
 */
void Snib_Eradicate()
{
    Err err;
    SnibPtr snib;

    err = FtrGet(kKeyringCreatorID, k_SnibFtrId, (UInt32*) &snib);
    if (err == ftrErrNoSuchFeature)
	/* Key was already removed */
	return;

    if (!err) {
	err = MemSet(snib, sizeof (SnibStruct), 0);
	if (!err) {
	    err = MemPtrFree(snib);
	    if (!err)
		err = FtrUnregister(kKeyringCreatorID, k_SnibFtrId);
	}
    }

    if (err) {
	/* I hope it is okay to display an error dialog.  This will
	 * prevent other alarms to be triggered in a timely manner,
	 * but this should never happen anyway.
	 *
	 * Also we really want to know when removing keys doesn't
	 * work as this is safety critical.
	 */
	ErrNonFatalDisplayIf(err, "Can't eradicate key");
    }
}

static SnibPtr Snib_GetSnib(Boolean create)
{
    Err err;
    SnibPtr snib;

    err = FtrGet(kKeyringCreatorID, k_SnibFtrId, (UInt32*) &snib);
    if (!err)
	return snib;
    if (!create)
	return NULL;

    snib = MemPtrNew (sizeof (SnibStruct));
    if (snib == NULL)
	err = memErrNotEnoughSpace;
    else
	err = MemPtrSetOwner(snib, 0);

    if (err) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
	return NULL;
    }
    FtrSet(kKeyringCreatorID, k_SnibFtrId, (UInt32) snib);
    return snib;
}


/*
 * Set a new expiry time.
 */
void Snib_SetExpiry(UInt32 newTime)
{
    UInt16  cardNo;
    LocalID dbID;
    SnibPtr snib = Snib_GetSnib (false);

    snib->expiryTime = newTime;
    SysCurAppDatabase(&cardNo, &dbID);
    AlmSetAlarm(cardNo, dbID, 0, newTime, true);
}

/*
 * Store the record key (hash of master password) for use later in
 * this session.
 */
void Snib_StoreRecordKey(UInt8 *newHash)
{
    Err err;
    SnibPtr snib = Snib_GetSnib (true);
    err = MemMove(snib->recordKey, newHash, k2DESKeySize);
    
    if (err)
	 UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
}


/* Retrieve the key hash from the snib if it exists, and return TRUE.
 * Otherwise, return FALSE.  */
Boolean Snib_RetrieveKey(UInt8* keyHash) {
    SnibPtr snib;
    UInt32  now;
    Err     err;

    snib = Snib_GetSnib(false);
    if (snib == NULL)
	return false;

    // If the timeout is too far in the future, then adjust it: this
    // makes it work OK if e.g. the clock has changed.

    now = TimGetSeconds();
    if (now > snib->expiryTime) {
	Snib_Eradicate ();
	return false;
    }

    if (now + gPrefs.timeoutSecs < snib->expiryTime)
	Snib_SetExpiry(now + gPrefs.timeoutSecs);

    err = MemMove(keyHash, snib->recordKey, k2DESKeySize);
    return err == errNone;
}
