/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

// =====================================================================
// List form

/*
 * TODO: Show category headings in the list.
 */

static TablePtr f_Table;
static ScrollBarPtr f_ScrollBar;
static FieldPtr f_LookUp;
static FormPtr f_ListForm;

/* Number of table rows that could possibly fit on the screen.  Some
 * of them might not be actually in use if there's less than a screen
 * of records. */
static UInt16 f_ScreenRows;

/* Number of records available to be shown in the table, after taking
 * into account categories and reserved records. */
static UInt16 f_NumListed;

/* Index of the first record displayed in the table.  Zero shows top
 * of table, etc. */
UInt16 f_FirstIdx;

static UInt16 f_FirstIndex;
static UInt16 f_SelectedIdx;

static GUI_SECTION Int16 ListForm_RecordIdx(Int16 row)
{
    Int16       idx = f_FirstIndex;
    Err         err;

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
    err = DmSeekRecordInCategory(gKeyDB, &idx, row, 
				 dmSeekForward, gPrefs.category);

    return err == errNone ? idx : -1;
}


/**
 * Draws a text at the given coordinate.  If the text is longer than
 * width it is abbreviated by dots.
 *
 * This is also called by Search function.  Therefore it must reside
 * in the default text section.
 */
void ListForm_DrawToFit(const Char* name, UInt16 len,
			Coord x, Coord y, Coord width)
{
    Coord textWidth;

    FntSetFont(stdFont);
    textWidth = FntCharsWidth(name, len);

    WinDrawChars(name, len, x, y);
    if (textWidth > width) 
    {
	Coord dotsLen;
	dotsLen = FntCharWidth('.') * 3;
	WinDrawChars("...", 3, x + width - dotsLen, y);
    }
}


static GUI_SECTION void ListForm_DrawCell(TablePtr UNUSED(table),
                              Int16 row, Int16 UNUSED(col), 
                              RectanglePtr bounds)
{
    /* This could be faster if we remembered the current position and
     * stepped forward to the next.
     */
    MemHandle   rec = 0;
    FieldHeaderType *recPtr = 0;
    Char const  *scrStr;
    UInt16      len;
    Int16       idx;
    static Char altBuf[maxStrIToALen + 1];

    /* Clear current cell content.  This is needed by PalmOS 3.3 and below */
    WinEraseRectangle(bounds, 0);

    idx = ListForm_RecordIdx(row); 
    if (idx == -1) 
	/* We reached the end of the table; return immediately. */
	return;

    rec = DmQueryRecord(gKeyDB, idx);
    if (!rec) {
        scrStr = "<no-record>";
	len = StrLen(scrStr);
	goto draw;
    }
    
    recPtr = MemHandleLock(rec); 
    len    = recPtr->len;
    scrStr = (Char *) (recPtr + 1);

    if (!len) {
        /* If there is no name, use the record index instead.  */
        altBuf[0] = '#';
        StrIToA(altBuf + 1, idx);
        scrStr = altBuf;
	len = StrLen(scrStr);
    }
 draw:
    ListForm_DrawToFit(scrStr, len, 
		       bounds->topLeft.x, bounds->topLeft.y, 
		       bounds->extent.x);
    
    if (recPtr)
        MemHandleUnlock(rec);
}

static GUI_SECTION void ListForm_DrawLockBitmap(void) {
    MemHandle bmpH;
    BitmapPtr bmpP;
    Boolean locked;

    locked = !Snib_RetrieveKey(NULL);

    bmpH = (MemHandle) DmGetResource
        (bitmapRsc, locked ? LockBitmap : UnlockBitmap);
    ErrFatalDisplayIf(!bmpH, "Missing bitmap");
    bmpP = MemHandleLock((MemHandle)bmpH);
    WinDrawBitmap(bmpP, 151, 1);
    MemPtrUnlock(bmpP);
    DmReleaseResource((MemHandle) bmpH);
}

/*
 * Update the table control, after querying the database to see how
 * many rows can be displayed.
 */
static GUI_SECTION void ListForm_UpdateTable(void)
{
    UInt16 row;
    f_NumListed = DmNumRecordsInCategory(gKeyDB, gPrefs.category);

    /* Mark all rows upto f_NumListed as usable.
     */
    for (row = 0; row < f_ScreenRows; row++) {
	TblSetRowUsable(f_Table, row, row < f_NumListed);
    }
}


static GUI_SECTION void ListForm_UpdateScrollBar(void)
{
    /*
     * Connect the scrollbar to the list.  The list cannot change
     * while this form is displayed: insertion, deletion, and renaming
     * all happen from inside the key details form.  Therefore, we
     * don't have to update the size of the scroll bar.
     */
    UInt16 max;
    max = f_NumListed <= f_ScreenRows ? 0 :f_NumListed - f_ScreenRows;
    if (f_FirstIdx > max)
	f_FirstIdx = max;
    SclSetScrollBar(f_ScrollBar, f_FirstIdx, 0, max, f_ScreenRows);
    f_FirstIndex = 0;
    DmSeekRecordInCategory(gKeyDB, &f_FirstIndex, f_FirstIdx, 
			   dmSeekForward, gPrefs.category);
}


static GUI_SECTION void ListForm_UpdateCategory(void)
{
    Category_UpdateName(f_ListForm, gPrefs.category);
}

static GUI_SECTION void ListForm_UpdateSelection(void)
{
    if (f_SelectedIdx >= f_FirstIdx
	&& f_SelectedIdx < f_FirstIdx + f_ScreenRows)
	TblSelectItem(f_Table, f_SelectedIdx - f_FirstIdx, 0);
    else
	TblUnhighlightSelection(f_Table);
}

static GUI_SECTION void ListForm_Update(void)
{
    ListForm_UpdateTable();
    ListForm_UpdateCategory();
    ListForm_UpdateScrollBar();
    
    FrmDrawForm(f_ListForm);
    ListForm_UpdateSelection();
    ListForm_DrawLockBitmap();
}

static GUI_SECTION void ListForm_InitTable(void)
{
    UInt16 row;

    /* Get the total number of rows allocated.  */
    f_ScreenRows = TblGetNumberOfRows(f_Table);

    /* Mark all rows as custom
     */
    for (row = 0; row < f_ScreenRows; row++) {
	TblSetItemStyle(f_Table, row, 0, customTableItem);
    }
    TblSetColumnUsable(f_Table, 0, true);
    
    TblSetCustomDrawProcedure(f_Table, 0,
                              (TableDrawItemFuncPtr) ListForm_DrawCell);

    TblHasScrollBar(f_Table, true);
}


static GUI_SECTION void ListForm_FormOpen(void)
{
    f_ListForm = FrmGetActiveForm();
    f_Table = UI_GetObjectByID(f_ListForm, ID_KeyTable);
    f_ScrollBar = UI_GetObjectByID(f_ListForm, ID_KeyTableScrollBar);
    f_LookUp = UI_GetObjectByID(f_ListForm, LookUpFld);
    f_SelectedIdx = kNoRecord;

    ListForm_InitTable();
    ListForm_Update();
    FrmSetFocus(f_ListForm, FrmGetObjectIndex(f_ListForm, LookUpFld));
}


static GUI_SECTION Boolean ListForm_SelectIndex(UInt16 listIdx)
{
    UInt16      idx;
    Err         err;

    /* Map from a position within this category to an overall
     * record index. */
    idx = 0;
    err = DmSeekRecordInCategory(gKeyDB, &idx, listIdx,
				 dmSeekForward, gPrefs.category);
    ErrFatalDisplayIf(err, __FUNCTION__ ": selected item doesn't exist");
    KeyEdit_GotoRecord(idx);
    return false;
}


static GUI_SECTION void ListForm_NewKey(void)
{
     KeyEdit_GotoRecord(kNoRecord);
}


/*
 * Scroll to the record.  Update table and scrollbar.
 *
 * It can't be less than zero of course, but also we don't allow
 * whitespace at the bottom if there are enough rows to fill the
 * display.  However we leave the display as close as possible to
 * where the user put it last.  
 */
static GUI_SECTION void ListForm_Scroll(UInt16 newPos)
{
    UInt16 oldPos = f_FirstIdx;
    f_FirstIdx = newPos;
    ListForm_UpdateScrollBar();
    if (f_FirstIdx != oldPos) {
	TblUnhighlightSelection(f_Table);
	TblMarkTableInvalid(f_Table);
	TblRedrawTable(f_Table);
	ListForm_UpdateSelection();
    }
}


static GUI_SECTION void ListForm_LookUpItem(Char *item)
{
    UInt16 idx, itemLen, matchLen;
    UInt16 catpos;
    MemHandle rec;
    FieldHeaderType *fldHeader;
    Int16 compare;
    if (!item || !(itemLen = StrLen(item))) {
	f_SelectedIdx = kNoRecord;
	ListForm_UpdateSelection();
	return;
    }

    idx = 0;
    for (;;) {
	rec = DmQueryNextInCategory(gKeyDB, &idx, gPrefs.category);
	if (!rec) {
	    /* scroll to the end */
	    ListForm_Scroll(f_NumListed);
	    break;
	}
	fldHeader = MemHandleLock(rec); 
	if (fldHeader) {
	    compare = TxtGlueCaselessCompare((Char *) (fldHeader + 1), 
					     fldHeader->len, NULL,
					     item, itemLen, &matchLen);
	    MemHandleUnlock(rec);
	    if (compare >= 0) {
		catpos = DmPositionInCategory(gKeyDB, idx, gPrefs.category);
		if (matchLen == itemLen)
		    f_SelectedIdx = catpos;
		else
		    f_SelectedIdx = kNoRecord;
		ListForm_Scroll(catpos);
		ListForm_UpdateSelection();
		break;
	    }
	}
	idx++;
    }
}
    
static GUI_SECTION void ListForm_CategoryTrigger(void)
{
    if (Category_Selected(&gPrefs.category, true)) {
        ListForm_Update();
	ListForm_LookUpItem(FldGetTextPtr(f_LookUp));
    }
}


GUI_SECTION Boolean ListForm_HandleEvent(EventPtr event)
{
    Boolean result = false;
    
    switch (event->eType) {
    case ctlSelectEvent:
        switch (event->data.ctlSelect.controlID) {
        case LockBtn:
            Snib_Eradicate();
            break;

        case NewKeyBtn:
            ListForm_NewKey();
            result = true;
            break;

        case CategoryTrigger:
            ListForm_CategoryTrigger();
            return true;
        }
        break;

    case frmOpenEvent:
        ListForm_FormOpen();
        return true;

    case frmUpdateEvent:
        ListForm_Update();
        return true;

    case menuEvent:
        if (Common_HandleMenuEvent(event)) {
	    /* We may have left the form.  Update the lock bitmap
	     * on return.
	     */
	    ListForm_DrawLockBitmap();
	    return true;
	}
        break;

    case sclRepeatEvent:
        ListForm_Scroll(event->data.sclRepeat.newValue);
        break;

    case tblSelectEvent:
	if (event->data.tblSelect.tableID != ID_KeyTable)
	    break;
	f_SelectedIdx = f_FirstIdx + event->data.tblSelect.row;
	ListForm_UpdateSelection();
        return ListForm_SelectIndex(f_SelectedIdx);

    case keyDownEvent:
	if (TxtCharIsHardKey(event->data.keyDown.modifiers, 
			     event->data.keyDown.chr)) {
	    /* Select next category if hard key was pressed */
	    gPrefs.category = CategoryGetNext (gKeyDB, gPrefs.category);
	    ListForm_Update();
	    ListForm_LookUpItem(FldGetTextPtr(f_LookUp));
	    return true;
	} else if (event->data.keyDown.chr == pageUpChr) {
            ListForm_Scroll(f_FirstIdx > f_ScreenRows ? 
			    f_FirstIdx - f_ScreenRows : 0);
            return true;
        } else if (event->data.keyDown.chr == pageDownChr) {
            ListForm_Scroll(f_FirstIdx + f_ScreenRows);
            return true;
        } else if (event->data.keyDown.chr == chrLineFeed) {
	    if (f_SelectedIdx != kNoRecord)
		return ListForm_SelectIndex(f_SelectedIdx);
	} else if (FldHandleEvent (f_LookUp, event)) {
	    /* user entered a new char... */
	    ListForm_LookUpItem(FldGetTextPtr(f_LookUp));
	    return true;
	}
        break;

    case fldChangedEvent:
	ListForm_LookUpItem(FldGetTextPtr(f_LookUp));
	return true;

    default:
        ;       
    }

    return result;
}
