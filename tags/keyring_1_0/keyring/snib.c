/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * GNU Keyring -- store passwords securely on a handheld
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
 * check it.  */



/*
 * If the keyring is unlocked, then this is the handle of a record
 * which contains the unencrypted session key.  */
MemHandle        g_SnibHandle;
SnibPtr          g_Snib;
DmOpenRef        g_SnibDB;

#define k_SnibDBName "Keys-Gtkr-Temp"

#define k_SnibDBType 'GkyT'

#define k_SnibVersion 1

#define OFFSET(st, mem) ((char *) &(st->mem) - (char *) (st))

/*
 * Try to open an existing session key database.  Check its version.
 * If the version is wrong, delete the db and return nothing.  */
static Err Snib_TryExistingDB(void)
{
    Int16	cardNo;
    LocalID	dbID;
    Err		err;
    UInt16      version;

    cardNo = 0;
    dbID = DmFindDatabase(cardNo, k_SnibDBName);
    if (!dbID)
	return DmGetLastErr();
    
    if ((err = DmDatabaseInfo(cardNo, dbID, 0, 0,
			      &version,
			      0, 0, 0, 0,
			      0, 0, 0, 0)))
	return err;

    if (version != k_SnibVersion) {
	if ((err = DmDeleteDatabase(cardNo, dbID)))
	    return err;

	/* Deleted because we can't use it. */
	return 0;
    }

    g_SnibDB = DmOpenDatabase(cardNo, dbID, dmModeReadWrite);
    if (!g_SnibDB)
	return DmGetLastErr();

    g_SnibHandle = DmGetRecord(g_SnibDB, 0);
    if (!g_SnibHandle)
	return DmGetLastErr();

    g_Snib = MemHandleLock(g_SnibHandle);

    return 0;
}


static Err Snib_CreateDB(void)
{
    Err		err;
    UInt16	cardNo = 0;
    Boolean	isResource = false;
    LocalID	dbID;
    UInt16	version = k_SnibVersion;
    UInt16	pos = 0;

    err = DmCreateDatabase(cardNo, k_SnibDBName,
			   kKeyringCreatorID, k_SnibDBType,
			   isResource);
    if (err)
	return err;

    dbID = DmFindDatabase(cardNo, k_SnibDBName);
    if (!dbID)
	return DmGetLastErr();

    if ((err = DmSetDatabaseInfo(cardNo, dbID,
				 0, 0, &version, 0,
				 0, 0, 0, 0,
				 0, 0, 0)))
	return err;

    g_SnibDB = DmOpenDatabase(cardNo, dbID, dmModeReadWrite);
    if (!g_SnibDB)
	return DmGetLastErr();

    g_SnibHandle = DmNewRecord(g_SnibDB, &pos, sizeof (SnibStruct));
    if (!g_SnibHandle)
	return DmGetLastErr();

    g_Snib = MemHandleLock(g_SnibHandle);
    if (!g_Snib)
	return DmGetLastErr();

    if ((err = DmSet(g_Snib, 0, sizeof (SnibStruct), 0)))
	return err;
    
    return 0;
}

/*
 * We store the unlocked session key in a temporary database
 * not marked for backup.
 */
Err Snib_Init(void)
{
    Err err;
    
    ErrNonFatalDisplayIf(g_SnibDB, "g_SnibDB already open");

    err = Snib_TryExistingDB();

    if ((err == 0  &&  !g_SnibDB) || err == dmErrCantFind) {
	err = Snib_CreateDB();
    }
    if (err)
	goto out;

 out:
    if (err) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }

    return err;
}


/*
 * Release all records and close the database, we're leaving Keyring
 * (but may be coming back.)
 */
void Snib_Close(void)
{
    Err err;

    MemHandleUnlock(g_SnibHandle);
    
    if ((err = DmReleaseRecord(g_SnibDB, 0, true))) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }
    
    if ((err = DmCloseDatabase(g_SnibDB))) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }
}


/*
 * Reset the expiry time to zero, and also destroy the session key.
 */
void Snib_Eradicate(void)
{
    Err		err;
    
    err = DmSet(g_Snib, 0, sizeof (SnibStruct), 0);

    if (err) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }
}


/*
 * Set a new expiry time.
 */
void Snib_SetExpiry(UInt32 newTime)
{
    Err		err;
    
    err = DmWrite(g_Snib, OFFSET(g_Snib, expiryTime),
		  &newTime, sizeof newTime);

    if (err) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }
}



/*
 * Calculate the hash of a password and store it in the snib database.
 * This is called as the keyring is unlocked, so that we always have
 * the hash available in the future for convenient access.
 */
Err Snib_StoreFromPasswd(Char *passwd)
{
    UInt8 hash[kMD5HashSize];
    Err err;
    Int16 len;

    len = StrLen(passwd);

    err = EncDigestMD5(passwd, len, hash);
    if (err) {
         UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);
         return err;
    }

    Snib_StoreRecordKey(hash);

    return 0;
}


/*
 * Store the record key (hash of master password) for use later in
 * this session.
 */
void Snib_StoreRecordKey(UInt8 *newHash)
{
    Err		err;
    
    err = DmWrite(g_Snib, OFFSET(g_Snib, recordKey[0]),
		  newHash, k2DESKeySize);
    
    if (err) {
	UI_ReportSysError2(ID_SnibDatabaseAlert, err, __FUNCTION__);
    }
}
