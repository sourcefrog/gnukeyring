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

/**
 * This is the same as TxtGlueParamString, except that it works
 * even if International Feature Set is not present.
 *
 * XXX: This only works if there is at most one place where the
 * param is inserted.  This is good enough for keyring though.
 */
Char* UI_TxtParamString(const Char *inTemplate, 
			const Char *param0, const Char *param1, 
			const Char *param2, const Char *param3)
{
    UInt32 romVersion;
    
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion >= sysMakeROMVersion(3, 5, 0, sysROMStageRelease, 0)) {

	return TxtParamString(inTemplate, param0, param1, param2, param3);

    } else { 	
	/* we cannot use TxtParamString() */

	/* Hack, hack...  
	 * This works for Palm OS calling conventions
	 */
	const Char **params = &param0;
	MemHandle h;
	Char *result;
	UInt16 i, j;
	UInt16 occurences[4];
	UInt16 len = StrLen(inTemplate);

	for (i = 0; i < 4; i++) {
	    if (!params[i])
		continue;
	    
	    /* Use TxtGlueReplaceStr to find number of occurences. */
	    occurences[i] = TxtGlueReplaceStr
		((Char *)inTemplate, 0xffff, NULL, i);
	    for (j = 0; j < i; j++) {
		if (!params[j])
		    continue;
		/* We must also handle repeated replacements. */
		occurences[i] += occurences[j] * 
		    TxtGlueReplaceStr((Char *)params[j], 0xffff, NULL, i);
	    }
	    len += (StrLen(param0) - 2) * occurences[i];
	}
	/* Now that we know the length we do the replacement */
	h = MemHandleNew(len+1);
	if (!h)
	    return NULL;

	result = MemHandleLock(h);
	StrNCopy(result, inTemplate, len);
	for (i = 0; i < 4; i++) {
	    if (!params[i])
		continue;
	    TxtGlueReplaceStr(result, len, params[i], i);
	}
	return result;
    }
}
