/* -*- c-indentation-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: t; -*-
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@humbug.org.au>
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
#include "category.h"
#include "listform.h"
#include "keydb.h"

// =====================================================================
// List form

/* TODO: Try to avoid calling DmNumRecordsInCategory quite so often:
 * once we know how many records there are we should remember it!  */


static Int16 ListForm_RecordIdx(Int16 itemNum)
{
    Int16	idx = 0;
    Err		err;

    /* FIXME: We need to skip the first few reserved records, but that
     * depends on the category: if it is zero (if that's their
     * category) or all, then we must increase the itemNum; otherwise
     * not.
     *
     * Also, we need to selectively reduce the number of records in
     * the list by that amount, and also compensate when mapping list position
     * to record idx.
     *
     * Is there no "hidden" bit we can set to avoid all this?
     */

    itemNum += Keys_IdxOffsetReserved();
    
    err = DmSeekRecordInCategory(gKeyDB, &idx, itemNum,
				 dmSeekForward, gPrefs.category);

    if (err != errNone) {
	return -1;
    } 

    return idx;
}

static void ListForm_ListDraw(Int16 itemNum,
			      RectanglePtr bounds,
			      Char * UNUSED(*data))
{
    /* We keep deleted records at the end, so the first N records will
     * be ones we can draw. */

    /* This could be faster if we remembered the current position and
     * stepped forward to the next.  However it's not worth optimizing
     * since it will likely change to be a table in the future. */
    MemHandle	rec = 0;
    Char       *recPtr = 0, *scrStr;
    UInt16	len;
    Char	altBuf[10];
    Int16	idx;

    ErrFatalDisplayIf(itemNum > 10000, __FUNCTION__ ": unreasonable itemnum");

    idx = ListForm_RecordIdx(itemNum);
    if (idx == -1) {
    	scrStr = "<err>";
	goto draw;
    }

    rec = DmQueryRecord(gKeyDB, idx);
    if (!rec) {
	scrStr = "<no-record>";
	goto draw;
    }
    
    recPtr = MemHandleLock(rec);
    if (!recPtr) {
	scrStr = "<no-ptr>";
	goto draw;
    }
    
    if (!*recPtr) {
	// If there is no name, use the record index instead
	altBuf[0] = '#';
	StrIToA(altBuf + 1, idx);
	scrStr = altBuf;
    } else {
	scrStr = recPtr;
    }

 draw:
    len = StrLen(scrStr);
    WinDrawChars(scrStr, len, bounds->topLeft.x, bounds->topLeft.y);
    
    if (recPtr)
	MemHandleUnlock(rec);
}


static void ListForm_FormOpen(void) {
    FrmUpdateForm(FrmGetActiveFormID(), ~0);
    FrmDrawForm(FrmGetActiveForm());
}


/*
 * Return the number of listed records, taking into account the
 * current category and omitting the records reserved for the master
 * password hash and the encrypted session key.
 */
static Int16 ListForm_GetNumListed(void) {
    return DmNumRecordsInCategory(gKeyDB, gPrefs.category) -
	Keys_IdxOffsetReserved();
}


static Boolean ListForm_Update(int updateCode) {
    FormPtr		frm;
    ListPtr		list;
    UInt16		numRows;
    ScrollBarPtr 	scl;
    UInt16 		top, visRows, max;

    frm = FrmGetActiveForm();
    list = (ListPtr) UI_GetObjectByID(frm, KeysList);
    numRows = ListForm_GetNumListed();
    
    LstSetListChoices(list, 0, numRows);
    LstSetDrawFunction(list, ListForm_ListDraw);

    visRows = LstGetVisibleItems(list);
    
    // Select most-recently-used record, if any.
    if (gKeyPosition >= numRows) {
	gKeyPosition = gKeyRecordIndex = kNoRecord;
	top = 0;
    } else {
	LstSetSelection(list, gKeyPosition);
	LstMakeItemVisible(list, gKeyPosition);
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

    if (updateCode & updateCategory) {
	// Set up the category name in the trigger
	Category_UpdateName(frm, gPrefs.category);
    }

    FrmDrawForm(frm);
    
    return true;
}


static Boolean ListForm_ListSelect(EventPtr event) {
    Int16	listIdx, idx;
    Err		err;
    if (event->data.lstSelect.listID != KeysList)
	return false;

    if (Unlock_CheckTimeout() || UnlockForm_Run()) {
	/* Map from a position within this category to an overall
	 * record index. */
	listIdx = event->data.lstSelect.selection
	     + Keys_IdxOffsetReserved();
	idx = 0;
	err = DmSeekRecordInCategory(gKeyDB, &idx, listIdx,
				     dmSeekForward, gPrefs.category);
	gKeyRecordIndex = idx;
	gKeyPosition = listIdx;
	FrmGotoForm(KeyEditForm);
    }
    return true;
}


static void ListForm_NewKey(void) {
    gKeyRecordIndex = gKeyPosition = kNoRecord;
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

	case CategoryTrigger:
	    Category_Selected(&gPrefs.category, true);
	    break;
	}
	break;

    case frmOpenEvent:
	ListForm_FormOpen();
	result = true;
	break;

    case frmUpdateEvent:
	result = ListForm_Update(event->data.frmUpdate.updateCode);
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


