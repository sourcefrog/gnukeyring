/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool
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
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "uiutil.h"
#include "passwd.h"


// =====================================================================
// List form

static void ListForm_ListDraw(Int16 itemNum,
			      RectanglePtr bounds,
			      Char * UNUSED(*data))
{
    /* We keep deleted records at the end, so the first N records will
     * be ones we can draw. */
    MemHandle rec = 0;
    Char * recPtr = 0, *scrStr;
    UInt16 len;
    Char altBuf[30];
    UInt16 recPos;

    ErrFatalDisplayIf(!gKeyDB, __FUNCTION__ ":!gKeyDB");
    ErrFatalDisplayIf(itemNum > 100, __FUNCTION__ ":out of range");
    
    recPos = DmPositionInCategory(gKeyDB, itemNum, dmAllCategories);
    if (recPos == dmMaxRecordIndex)
	goto leave;

    rec = DmQueryRecord(gKeyDB, recPos);
    if (!rec) {
	scrStr = "<no-record>";
    } else { 
	recPtr = MemHandleLock(rec);
	if (!recPtr) {
	    scrStr = "<no-ptr>";
	} else {
	    if (!*recPtr) {
		// If there is no name, use the uniqueid instead
		UInt32 uniqueID;
	
		DmRecordInfo(gKeyDB, itemNum, 0, &uniqueID, 0);
		altBuf[0] = 23;		// shortcut symbol
		StrIToH(altBuf + 1, uniqueID);
		scrStr = altBuf;
	    } else
		scrStr = recPtr;
	}
    }

    len = StrLen(scrStr);
    WinDrawChars(scrStr, len, bounds->topLeft.x, bounds->topLeft.y);

    if (recPtr)
	MemHandleUnlock(rec);
    
 leave:
    ;
}


static void ListForm_BuildChoices(ListPtr list) {
    // DmNumRecordsInCategory doesn't count deleted records, which is what we
    // need.
    UInt16 numRows = DmNumRecordsInCategory(gKeyDB, dmAllCategories);
    LstSetListChoices(list, 0, numRows);
    LstSetDrawFunction(list, ListForm_ListDraw);
}


static void ListForm_FormOpen() {
    FormPtr frm = FrmGetActiveForm();
    ListPtr list = (ListPtr) UI_GetObjectByID(frm, KeysList);
    UInt16 numRows = DmNumRecordsInCategory(gKeyDB, dmAllCategories);
    ScrollBarPtr 	scl;
    UInt16 		top, visRows, max;
    
    ErrFatalDisplayIf(!list, "!listPtr");
    ListForm_BuildChoices(list);
    visRows = LstGetVisibleItems(list);
    
    // Select most-recently-used record, if any.
    if (gKeyRecordIndex >= numRows) {
	gKeyRecordIndex = kNoRecord;
	top = 0;
    } else {
	LstSetSelection(list, gKeyRecordIndex);
	LstMakeItemVisible(list, gKeyRecordIndex);
	top = list->topItem;
    }

    // Connect the scrollbar to the list.  The list cannot change
    // while this form is displayed: insertion, deletion, and renaming
    // all happen from inside the key details form.  Therefore, we
    // don't have to update the size of the scroll bar.
    scl = (ScrollBarPtr) UI_GetObjectByID(frm, KeysListScrollBar);
    list->attr.hasScrollBar = 1;
    max = numRows-visRows;

    SclSetScrollBar(scl, top, 0, max, visRows);

    FrmDrawForm(frm);
}


static Boolean ListForm_ListSelect(EventPtr event) {
    if (event->data.lstSelect.listID != KeysList)
	return false;

    if (Unlock_CheckTimeout() || UnlockForm_Run()) {
	gKeyRecordIndex = event->data.lstSelect.selection;
	FrmGotoForm(KeyEditForm);
    }
    return true;
}


static void ListForm_NewKey() {
    gKeyRecordIndex = kNoRecord;
    if (Unlock_CheckTimeout() || UnlockForm_Run()) {
	FrmGotoForm(KeyEditForm);
    }
}


static void ListForm_ScrollRepeat(EventPtr event) {
    ListPtr list = (ListPtr) UI_ObjectFromActiveForm(KeysList);
   
    int new = event->data.sclRepeat.newValue;
    int old = event->data.sclRepeat.value;
    WinDirectionType dir = new > old ? winDown : winUp;
    int count = new > old ? new - old : old - new;
    LstScrollList(list, dir, count);
}


static void ListForm_ScrollPage(WinDirectionType dir) {
    ListPtr list = (ListPtr) UI_ObjectFromActiveForm(KeysList);
    ScrollBarPtr scl = (ScrollBarPtr)
        UI_ObjectFromActiveForm(KeysListScrollBar);
    UInt16 visRows = LstGetVisibleItems(list);
    Int16 value, min, max, pageSize;

    LstScrollList(list, dir, visRows);
    SclGetScrollBar(scl, &value, &min, &max, &pageSize);
    value += (dir == winDown) ? visRows : -visRows;
    SclSetScrollBar(scl, value, min, max, pageSize);
}


Boolean ListForm_HandleEvent(EventPtr event) {
    Boolean result = false;
    
    switch (event->eType) {
    case ctlSelectEvent:
	switch (event->data.ctlSelect.controlID) {
	case NewKeyBtn:
	    ListForm_NewKey();
	    result = true;
	    break;
	}
	break;

    case frmOpenEvent:
	ListForm_FormOpen();
	result = true;
	break;

    case lstSelectEvent:
	result = ListForm_ListSelect(event);
	break;

    case menuEvent:
	if (!Common_HandleMenuEvent(event))
	    App_NotImplemented();
	result = true;
	break;

    case sclRepeatEvent:
	ListForm_ScrollRepeat(event);
	break;

    case keyDownEvent:
        if (event->data.keyDown.chr == pageUpChr) {
            ListForm_ScrollPage(winUp);
            result = true;
        }
        else if (event->data.keyDown.chr == pageDownChr) {
            ListForm_ScrollPage(winDown);
            result = true;
        }
        break;

    default:
	;	
    }

    return result;
}


