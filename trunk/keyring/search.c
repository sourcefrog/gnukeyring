/*
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2002-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

void Search(FindParamsPtr findParams, Boolean hasGlobals)
{
    DmOpenRef keyDB;
    Boolean done;
    UInt16 recordNum;
    UInt8 checkEventCounter = 16;
    MemHandle handle;
    FieldHeaderType *fldHeader;
    UInt16 fldIndex;
    UInt32 pos;
    UInt16 len;
    LocalID dbID;
    Int16 cardNo;
    RectangleType r;
    Boolean hasSnib = false;
    CryptoKey *encryptionKey = NULL;
    Int16 matchField;
    Char *text;
 
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

    if (hasGlobals) {
	/* Without globals we can't decrypt the database, because GLib
	 * libraries (such as DES) currently need globals to work.
	 * This bug is already reported to prc-tools...
	 *
	 * So we only allow searching the full database when the find
	 * dialog was invoked within keyring.
	 */
	encryptionKey = MemPtrNew(sizeof(CryptoKey));
	hasSnib = Snib_RetrieveKey(encryptionKey);
    }
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
	
	matchField = -1;
	if (hasSnib) {
	    UnpackedKeyType *unpacked;
	    Record_Unpack(handle, &unpacked, encryptionKey);
	    for (fldIndex = 0; 
		 matchField < 0 && fldIndex < unpacked->numFields; 
		 fldIndex++) {
		fldHeader = (FieldHeaderType *)
		    (unpacked->plainText + unpacked->fieldOffset[fldIndex]);

		if (fldHeader->fieldID < 3 || fldHeader->fieldID == 255) {
		    char tmp;
		    text = (char*) (fldHeader + 1);
		    tmp = text[fldHeader->len];
		    text[fldHeader->len] = 0;
		    if (TxtGlueFindString((char*) (fldHeader + 1),
					  findParams->strToFind, &pos, &len))
			matchField = fldIndex;
		    text[fldHeader->len] = tmp;
		}
	    }
	    Record_Free(unpacked);
	} else {
	    fldHeader = MemHandleLock(handle);
	    text = MemPtrNew(fldHeader->len + 1);
	    if (text) {
		MemMove(text, (char *) (fldHeader + 1), fldHeader->len);
		text[fldHeader->len] = 0;
		if (TxtGlueFindString(text, findParams->strToFind, &pos, &len))
		    matchField = 0;
		MemPtrFree(text);
	    }
	    MemHandleUnlock(handle);
	}

	if (matchField >= 0) {
	    if (FindSaveMatch(findParams, recordNum, pos, matchField, len, 
			      cardNo, dbID))
		break;

	    fldHeader = MemHandleLock(handle);
	    FindGetLineBounds(findParams, &r);
	    WinGlueDrawTruncChars((char*) (fldHeader + 1), fldHeader->len,
				  r.topLeft.x, r.topLeft.y, r.extent.x);
	    findParams->lineNumber++;
	    MemHandleUnlock(handle);
	}
	recordNum++;
    }
    if (encryptionKey) {
	CryptoDeleteKey(encryptionKey);
	MemPtrFree(encryptionKey);
    }

    DmCloseDatabase(keyDB);
}
