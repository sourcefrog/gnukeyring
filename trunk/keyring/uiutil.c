/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999 Martin Pool
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

#include <Pilot.h>
#include <Password.h>
#include <Encrypt.h>

#include "uiutil.h"


// ======================================================================
// User-interface utilities
FieldPtr UI_GetFocusObjectPtr(void) {
    FormPtr frm;
    Word focus;
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


VoidPtr UI_ObjectFromActiveForm(Word objectID)
{
    FormPtr currentForm = FrmGetActiveForm();
    return FrmGetObjectPtr(currentForm, 
			   FrmGetObjectIndex(currentForm, objectID));
}


VoidPtr UI_GetObjectByID(FormPtr frm, Word objectID) {
    return FrmGetObjectPtr(frm,
			   FrmGetObjectIndex(frm, objectID));
}


int UI_ScanForFirst(FormPtr frm, Word const * map) {
    Int i;

    for (i = 0; ; i += 2) {
	if (map[i] == (Word) -1)
	    break;
	
	if (CtlGetValue(UI_GetObjectByID(frm, map[i+1]))) {
	    return map[i];
	}
    }

    return -1;
}


void UI_ScanAndSet(FormPtr frm, Word const *map, Word value) {
    Int i;

    for (i = 0; ; i += 2) {
	if (map[i] == (Word) -1)
	    break;

	if (map[i] == value)
	    CtlSetValue(UI_GetObjectByID(frm, map[i+1]), true);
    }
}


int UI_ScanUnion(FormPtr frm, Word const * map) {
    Int i, result = 0;

    for (i = 0; ; i += 2) {
	if (map[i] == (Word) -1)
	    break;
	
	if (CtlGetValue(UI_GetObjectByID(frm, map[i+1])))
	    result |= map[i];
    }

    return result;
}



void UI_UnionSet(FormPtr frm, Word const * map, Word value) {
    Int i;

    for (i = 0; ; i += 2) {
	if (map[i] == (Word) -1)
	    break;

	CtlSetValue(UI_GetObjectByID(frm, map[i+1]),
		    (map[i] & value) ? true : false);
    }
}
