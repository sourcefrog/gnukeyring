/*
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001, 2002
 *   by Martin Pool, Jochen Hoenicke <{mbp,hoenicke}@users.sourceforge.net>
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

#include "includes.h"

static void SearchDrawItem(Char* name, Coord x, Coord y, Coord width)
{
    Coord textWidth;
    Int16 nameLen;

    FntSetFont(stdFont);
    nameLen = StrLen(name);
    textWidth = FntCharsWidth(name, nameLen);

    WinDrawChars(name, nameLen, x, y);
    if (textWidth > width) 
    {
	Coord dotsLen;
	dotsLen = FntCharWidth('.') * 3;
	WinDrawChars("...", 3, x + width - dotsLen, y);
    }
}

void Search(FindParamsPtr findParams)
{
    DmOpenRef keyDB;
    Boolean done;
    UInt16 recordNum;
    UInt8 checkEventCounter = 16;
    MemHandle handle;
    Char *rec;
    UInt32 pos;
    UInt16 len;
    LocalID dbID;
    Int16 cardNo;
    RectangleType r;
    Boolean hasSnib;
    UInt8 encryptionKey[k2DESKeySize];
    Int16 matchField;

    findParams->more = true;

    /* We open database readonly and assume latest version. */
    keyDB = DmOpenDatabaseByTypeCreator(kKeyDBType, kKeyringCreatorID,
					dmModeReadOnly);
    if (!keyDB || DmOpenDatabaseInfo(keyDB, &dbID, NULL, NULL, &cardNo, NULL))
    {
	findParams->more = false;
	return;
    }

    handle = DmGetResource(strRsc, KeyringFindStr);
    done = FindDrawHeader(findParams, MemHandleLock(handle));
    MemHandleUnlock(handle);
    if (done)
	return;

    hasSnib = Snib_RetrieveKey(encryptionKey);
    recordNum = findParams->recordNum;

    while (true)
    {
	if (hasSnib || !--checkEventCounter)
	{
	    if (EvtSysEventAvail(true))
		break;
	    checkEventCounter = 16;
	}

	handle = DmQueryNextInCategory(keyDB, &recordNum, dmAllCategories);
	if (!handle)
	{
	    /* We reached the last record */
	    findParams->more = false;
	    break;
	}
	
	rec = MemHandleLock(handle);
	matchField = -1;
	if (hasSnib) {
	    UnpackedKeyType unpacked;
	    Keys_UnpackRecord(rec, &unpacked, encryptionKey);
	    if (unpacked.nameHandle) {
		if (TxtGlueFindString(MemHandleLock(unpacked.nameHandle),
				      findParams->strToFind, &pos, &len))
		    matchField = 0;
		MemHandleUnlock(unpacked.nameHandle);
	    }
	    if (matchField < 0 && unpacked.acctHandle)
	    {
		if (TxtGlueFindString(MemHandleLock(unpacked.acctHandle),
				      findParams->strToFind, &pos, &len))
		    matchField = 1;
		MemHandleUnlock(unpacked.acctHandle);
	    }
	    if (matchField < 0 && unpacked.passwdHandle)
	    {
		if(TxtGlueFindString(MemHandleLock(unpacked.passwdHandle),
				     findParams->strToFind, &pos, &len))
		    matchField = 2;
		MemHandleUnlock(unpacked.passwdHandle);
	    }
	    if (matchField < 0 && unpacked.notesHandle)
	    {
		if (TxtGlueFindString(MemHandleLock(unpacked.notesHandle), 
				      findParams->strToFind, &pos, &len))
		    matchField = 3;
		MemHandleUnlock(unpacked.notesHandle);
	    }
	    UnpackedKey_Free(&unpacked);
	} 
	else if (TxtGlueFindString(rec, findParams->strToFind, &pos, &len))
	    matchField = 0;

	MemHandleUnlock(handle);

	if (matchField >= 0) {
	    if (FindSaveMatch(findParams, recordNum, pos, matchField, len, 
			      cardNo, dbID))
		break;

	    FindGetLineBounds(findParams, &r);
	    SearchDrawItem(rec, r.topLeft.x, r.topLeft.y, r.extent.x);
	    findParams->lineNumber++;
	}
	recordNum++;
    }

    MemSet(encryptionKey, sizeof(encryptionKey), 0);
    DmCloseDatabase(keyDB);
}
