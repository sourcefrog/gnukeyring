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
 * TODO: Check that the terminating NULs in the strings are accounted
 * for correctly.
 *
 * TODO: Is it possible we could be overflowing the stack?
 */

#include "includes.h"


void UnpackedKey_Free(UnpackedKeyPtr u)
{
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



Err KeyRecord_GetCategory(Int16 idx, UInt16 *category)
{
    UInt16		attr;
    Err			err;

    if ((err = DmRecordInfo(gKeyDB, idx, &attr, 0, 0)))
	return err;

    *category = (attr & dmRecAttrCategoryMask);

    return 0;
}
