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

#include "includes.h"


// ======================================================================
// User-interface utilities


void UI_ReportSysError2(UInt16 msgID, Err err, char const *where) 
{
    Char buf[256];

    *buf = '\0';		/* in case nothing is inserted? */
    SysErrString(err, buf, (UInt16) sizeof buf);
    FrmCustomAlert(msgID, buf, where, 0);
}


void App_NotImplemented(void)
{
    FrmAlert(ID_NotImplementedAlert);
}



FieldPtr UI_GetFocusObjectPtr(void)
{
    FormPtr frm;
    UInt16 focus;
    FormObjectKind objType;
	
    frm = FrmGetActiveForm();
    focus = FrmGetFocus(frm);
    if (focus == noFocus)
	return 0;
		
    objType = FrmGetObjectType(frm, focus);
	
    if (objType == frmFieldObj)
	return FrmGetObjectPtr(frm, focus);

    return 0;
}


void * UI_GetObjectByID(FormPtr frm, UInt16 objectID)
{
    return FrmGetObjectPtr(frm,
			   FrmGetObjectIndex(frm, objectID));
}


int UI_ScanForFirst(FormPtr frm, UInt16 const * map)
{
    Int16 i;

    for (i = 0; ; i += 2) {
	if (map[i] == (UInt16) -1)
	    break;
	
	if (CtlGetValue(UI_GetObjectByID(frm, map[i+1]))) {
	    return map[i];
	}
    }

    return -1;
}


void UI_ScanAndSet(FormPtr frm, UInt16 const *map, UInt16 value)
{
    Int16 i;

    for (i = 0; ; i += 2) {
	if (map[i] == (UInt16) -1)
	    break;

	if (map[i] == value)
	    CtlSetValue(UI_GetObjectByID(frm, map[i+1]), true);
    }
}


int UI_ScanUnion(FormPtr frm, UInt16 const * map)
{
    Int16 i, result = 0;

    for (i = 0; ; i += 2) {
	if (map[i] == (UInt16) -1)
	    break;
	
	if (map[i] && CtlGetValue(UI_GetObjectByID(frm, map[i+1])))
	    result |= map[i];
    }

    return result;
}



void UI_UnionSet(FormPtr frm, UInt16 const * map, UInt16 value)
{
    Int16 i;

    for (i = 0; ; i += 2) {
	if (map[i] == (UInt16) -1)
	    break;

	if (map[i] == 0)
	    FrmHideObject(frm, FrmGetObjectIndex(frm, map[i+1]));
	else
	    CtlSetValue(UI_GetObjectByID(frm, map[i+1]),
			(map[i] & value) ? true : false);
    }
}
