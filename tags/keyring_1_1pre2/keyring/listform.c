/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
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
#include "auto.h"
#include "keyedit.h"

// =====================================================================
// List form

/*
 * TODO: As a possible optimization, scroll the bitmap of the table
 * rather than redrawing it.  See ListViewScroll in the MemoPad
 * source.
 *
 * TODO: Show category headings in the list.
 *
 * TODO: Scroll to show newly-inserted items.
 */

static TablePtr f_Table;
static ScrollBarPtr f_ScrollBar;
static FormPtr f_ListForm;

/* Number of table rows that could possibly fit on the screen.  Some
 * of them might not be actually in use if there's less than a screen
 * of records. */
static Int16 f_ScreenRows;

/* Pixel width of the table */
static Int16 f_TableWidth, f_TableHeight;

/* Number of records available to be shown in the table, after taking
 * into account categories and reserved records. */
static Int16 f_NumListed;

/* Index of the first record displayed in the table.  Zero shows top
 * of table, etc. */
Int16 f_FirstIdx;

/* Width of '.' character in pixels */
static Int16 f_DotWidth;

static Int16 ListForm_RecordIdx(Int16 itemNum)
{
    Int16       idx = 0;
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
    
    err = DmSeekRecordInCategory(gKeyDB, &idx, itemNum,
                                 dmSeekForward, gPrefs.category);

    if (err != errNone) {
        return -1;
    } 

    return idx;
}


static void ListForm_DrawToFit(Char const * name, Int16 x, Int16 y)
{
    Int16 titleLen, width, titleWidth;
    Int16 charsToDraw;
    Boolean stringFit;

    charsToDraw = StrLen(name);

    width = f_TableWidth - x;
    titleWidth = width;
    titleLen = charsToDraw;
    FntCharsInWidth(name, &titleWidth, &titleLen, &stringFit);

    if (stringFit) {
        WinDrawChars(name, titleLen, x, y);
    } else {
        width -= (f_DotWidth * 3);
        while (titleWidth > width || 
               name[titleLen - 1] == ' ' || 
               name[titleLen - 1] == tabChr)
            {
                titleWidth -= FntCharWidth(name[--titleLen]);
            }
        WinDrawChars(name, titleLen, x, y);
        x += titleWidth;
        WinDrawChars("...", 3, x, y);
    }
}


static void ListForm_DrawCell(TablePtr UNUSED(table),
                              Int16 row, Int16 UNUSED(col), 
                              RectanglePtr bounds)
{
    /* We keep deleted records at the end, so the first N records will
     * be ones we can draw. */

    /* This could be faster if we remembered the current position and
     * stepped forward to the next.  However it's not worth optimizing
     * since it will likely change to be a table in the future. */
    MemHandle   rec = 0;
    Char const *recPtr = 0, *scrStr;
    Char        altBuf[10];
    Int16       idx = row;

    ErrFatalDisplayIf(row > 10000, __FUNCTION__ ": unreasonable itemnum");

    idx = ListForm_RecordIdx(row + f_FirstIdx); 
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
        /* If there is no name, use the record index instead.  At the
         * moment this skips over records that have been deleted, but
         * I think once we've included sorting that will not
         * happen. */
        altBuf[0] = '#';
        StrIToA(altBuf + 1, idx - kNumHiddenRecs);
        scrStr = altBuf;
    } else {
        scrStr = recPtr;
    }

 draw:
    /* TODO: Maybe add ellipsis if too wide? */
    ListForm_DrawToFit(scrStr, bounds->topLeft.x + 2, bounds->topLeft.y);
    
    if (recPtr)
        MemHandleUnlock(rec);
}


/*
 * Update the table control, after querying the database to see how
 * many rows can be displayed.
 */
static void ListForm_UpdateTable(void)
{
    Int16 row;
    Int16 lineHeight;
    Int16 dataHeight;
    Int16 maxRows;

    lineHeight = FntLineHeight();

    /* Get the total number of rows allocated.  */
    maxRows = TblGetNumberOfRows(f_Table);

    f_NumListed = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
    ErrNonFatalDisplayIf(f_NumListed > 30000,
                         "unreasonable numListed");

    f_ScreenRows = f_TableHeight / lineHeight;

    /* Work out which record should be at the top.  It can't be less
     * than zero of course, but also we don't allow whitespace at the
     * bottom if there are enough rows to fill the display.  However
     * we leave the display as close as possible to where the user put
     * it last. */
    if (f_FirstIdx > f_NumListed - f_ScreenRows)
         f_FirstIdx = f_NumListed - f_ScreenRows;
    if (f_FirstIdx < 0)
         f_FirstIdx = 0;

    /* Update all row controls, but also mark ones for which there is
     * no data as not usable.
     *
     * TODO: Try to avoid calling all the TblSet routines more than
     * once per invocation of the list form. */
    dataHeight = 0;
    for (row = 0; row < maxRows; row++) {
        if ((f_TableHeight >= dataHeight + lineHeight)
            && (row + f_FirstIdx < f_NumListed)) {
            /* Row is usable */
            TblSetRowHeight(f_Table, row, lineHeight);
            TblSetItemStyle(f_Table, row, 0, customTableItem);
            TblSetRowUsable(f_Table, row, true);
        } else {
            TblSetRowUsable(f_Table, row, false);
        }
        dataHeight += lineHeight;
    }
    TblSetColumnUsable(f_Table, 0, true);
    
    TblSetCustomDrawProcedure(f_Table, 0,
                              (TableDrawItemFuncPtr) ListForm_DrawCell);

    TblHasScrollBar(f_Table, true);
}


static void ListForm_UpdateScrollBar(void)
{
    /*
     * Connect the scrollbar to the list.  The list cannot change
     * while this form is displayed: insertion, deletion, and renaming
     * all happen from inside the key details form.  Therefore, we
     * don't have to update the size of the scroll bar.
     */
    Int16 max;

    max = f_NumListed - f_ScreenRows;
    if (max < 0) {
        /* Less than one page of records. */
        max = 0;
    }
    SclSetScrollBar(f_ScrollBar, f_FirstIdx, 0, max, f_ScreenRows);
}




static void ListForm_UpdateCategory(void)
{
    Category_UpdateName(f_ListForm, gPrefs.category);
}



static void ListForm_Update(void)
{
    ListForm_UpdateTable();
    ListForm_UpdateCategory();
    ListForm_UpdateScrollBar();
    
    FrmDrawForm(f_ListForm);
}


static void ListForm_FormOpen(void) {
    RectangleType r;
       
    f_ListForm = FrmGetActiveForm();
    f_Table = UI_GetObjectByID(f_ListForm, ID_KeyTable);
    f_ScrollBar = UI_GetObjectByID(f_ListForm, ID_KeyTableScrollBar);

    TblGetBounds(f_Table, &r);
    f_TableHeight = r.extent.y;
    f_TableWidth = r.extent.x;

    f_DotWidth = FntCharWidth('.');

    ListForm_Update();
}


static Boolean ListForm_TableSelect(EventPtr event)
{
    Int16       listIdx, idx;
    Err         err;
    if (event->data.tblSelect.tableID != ID_KeyTable)
        return false;

    /* Map from a position within this category to an overall
     * record index. */
    listIdx = f_FirstIdx + event->data.tblSelect.row;
    idx = 0;
    err = DmSeekRecordInCategory(gKeyDB, &idx, listIdx,
				 dmSeekForward, gPrefs.category);
    ErrFatalDisplayIf(err, __FUNCTION__ ": selected item doesn't exist");
    KeyEditForm_GotoRecord(idx);
    return true;
}


static void ListForm_NewKey(void) {
     KeyEditForm_GotoRecord(kNoRecord);
}


/*
 * Scroll if possible.  Update table and scrollbar.
 */
static void ListForm_Scroll(Int16 newPos) {
     if (newPos > f_NumListed - f_ScreenRows)
          newPos = f_NumListed - f_ScreenRows;
     if (newPos < 0)
          newPos = 0;
     
     f_FirstIdx = newPos;

     ListForm_UpdateScrollBar();
     TblMarkTableInvalid(f_Table);
     TblRedrawTable(f_Table);
}


static void ListForm_ScrollRepeat(EventPtr event) {
    int new = event->data.sclRepeat.newValue;
    ListForm_Scroll(new);
}


static void ListForm_ScrollPage(WinDirectionType dir) {
    Int16 newPos = f_FirstIdx +
        ((dir == winDown) ? +f_ScreenRows : -f_ScreenRows);
    ListForm_Scroll(newPos);
}


static void ListForm_CategoryTrigger(void)
{
    if (Category_Selected(&gPrefs.category, true)) {
        /* XXX: Is this really the only place we have to erase? */
        TblEraseTable(f_Table);
        ListForm_Update();
    }
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
            ListForm_CategoryTrigger();
            return true;
        }
        break;

    case frmOpenEvent:
        ListForm_FormOpen();
        return true;

    case menuEvent:
        if (!Common_HandleMenuEvent(event))
            App_NotImplemented();
        result = true;
        break;

    case sclRepeatEvent:
        ListForm_ScrollRepeat(event);
        break;

    case tblSelectEvent:
        return ListForm_TableSelect(event);

    case keyDownEvent:
        if (event->data.keyDown.chr == pageUpChr) {
            ListForm_ScrollPage(winUp);
            return true;
        } else if (event->data.keyDown.chr == pageDownChr) {
            ListForm_ScrollPage(winDown);
            return true;
        }
        break;

    default:
        ;       
    }

    return result;
}

