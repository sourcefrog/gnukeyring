/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
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
 * TODO: Check that the terminating NULs in the strings are accounted
 * for correctly.
 *
 * TODO: Is it possible we could be overflowing the stack?
 */

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "memutil.h"
#include "record.h"
#include "keydb.h"
#include "crypto.h"
#include "passwd.h"
#include "resource.h"
#include "snib.h"
#include "uiutil.h"
#include "auto.h"

static Int16 KeyDB_CompareRecords(void * rec1, void * rec2, Int16 other,
			 SortRecordInfoPtr info1,
			 SortRecordInfoPtr info2,
			 MemHandle appInfoHand);

// ======================================================================
// Key record manipulation


/* Compare records for sorting or sorted insertion.
 *
 * Because all records begin with the strz record name the comparison
 * is pretty simple: we sort in string order, except that deleted
 * records go to the end.  */
static Int16 KeyDB_CompareRecords(void * rec1, void * rec2,
				  Int16 UNUSED(other),
				  SortRecordInfoPtr info1,
				  SortRecordInfoPtr info2,
				  MemHandle UNUSED(appInfoHand))
{
    Int16 result;
    Char	*cp1, *cp2;

    if (info1 && (info1->attributes & dmRecAttrDelete))
	result = +1;
    else if (info2 && (info2->attributes & dmRecAttrDelete))
	result = -1;
    else {
	cp1 = (Char *) rec1;
	cp2 = (Char *) rec2;
	
	if (rec1  &&  !rec2)
	    result = -1;
	else if (!rec1  &&  rec2)
	    result = +1;
	else if (!rec1 && !rec2)
	    result = 0;
	else if (*cp1 && !*cp2)
	    result = -1;
	else if (!*cp1 && *cp2)
	    result = +1;
	else 
	    result = StrCompare(cp1, cp2);
    }
    return result;
}



void KeyRecord_Reposition(Char * name, UInt16 *idx, UInt16 *position)
{
    UInt16 	attr;
    UInt32 	uniqueID;
    MemHandle	moveHandle;
    Err 	err;
    
    DmRecordInfo(gKeyDB, *idx, &attr, &uniqueID, NULL);
    err = DmDetachRecord(gKeyDB, *idx, &moveHandle);
    if (err) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return;
    }
	
    *idx = DmFindSortPosition(gKeyDB, (void *) name, 0,
			      KeyDB_CompareRecords, 0);

    err = DmAttachRecord(gKeyDB, idx, moveHandle, 0);
    if (err) {
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return;
    }
    DmSetRecordInfo(gKeyDB, *idx, &attr, &uniqueID);

    *position = DmPositionInCategory(gKeyDB, *idx, gPrefs.category);
}


void UnpackedKey_Free(UnpackedKeyPtr u) {
    if (u->nameHandle)
	MemHandleFree(u->nameHandle);
    if (u->acctHandle)
	MemHandleFree(u->acctHandle);
    if (u->passwdHandle)
	MemHandleFree(u->passwdHandle);
    if (u->notesHandle)
	MemHandleFree(u->notesHandle);

    u->nameHandle = u->acctHandle = u->passwdHandle = u->notesHandle
	= NULL;
}


#if 0
static Err KeyRecord_SetCategory(Int16 idx, UInt16 category) {
    UInt16		attr;
    Err			err;

    if ((err = DmRecordInfo(gKeyDB, idx, &attr, 0, 0)))
	return err;

    attr = (attr & ~dmRecAttrCategoryMask)
	| (category & dmRecAttrCategoryMask);

    return DmSetRecordInfo(gKeyDB, idx, &attr, 0);
}
#endif


Err KeyRecord_GetCategory(Int16 idx, UInt16 *category) {
    UInt16		attr;
    Err			err;

    if ((err = DmRecordInfo(gKeyDB, idx, &attr, 0, 0)))
	return err;

    *category = (attr & dmRecAttrCategoryMask);

    return 0;
}
