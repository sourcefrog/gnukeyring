/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; indent-tabs-mode: t; -*-
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
#include "memutil.h"
#include "crypto.h"
#include "resource.h"
#include "snib.h"
#include "auto.h"
#include "uiutil.h"


/*
 * If the keyring is unlocked, then this is the handle of a record
 * which contains the unencrypted session key.
 */
MemHandle        g_SnibHandle;
SnibPtr          g_Snib;
DmOpenRef        g_SnibDB;

static const char *k_SnibDBName = "Keys-Gtkr-Temp";

static UInt32 k_SnibDBType = 'GkyT';

static const UInt32 k_SnibVersion = 1;

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
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    }

    return err;
}


void Snib_Close(void)
{
    Err err;

    MemHandleUnlock(g_SnibHandle);
    
    if ((err = DmReleaseRecord(g_SnibDB, 0, true))) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    }
    
    if ((err = DmCloseDatabase(g_SnibDB))) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    }
}


void Snib_SetExpiry(UInt32 newTime)
{
    Err		err;
    
    err = DmWrite(g_Snib, OFFSET(g_Snib, expiryTime),
		  &newTime, sizeof newTime);

    if (err) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    }
}


/*
 * Store the decrypted session key for use later in this session.
 */
void Snib_SetSessKey(UInt8 const *newKey)
{
    Err		err;
    
    err = DmWrite(g_Snib, OFFSET(g_Snib, sessKey[0]),
		  newKey, kDES3KeySize);

    if (err) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
    }
}
