/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool
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
#include "keyedit.h"
#include "keydb.h"
#include "uiutil.h"
#include "util.h"
#include "generate.h"
#include "record.h"
#include "export.h"
#include "category.h"

/* TODO: Show position and do paging within category
 *
 * TODO: Make the default category be set correctly when making a new
 * record. */


/* This keeps an unpacked version of the record currently being
 * edited.  They're periodically sync'd up; e.g. just before saving.
 *
 * It's a bit unfortunate to keep it in a global like this, but the
 * problem is that the date isn't stored by the GUI control, so we
 * need somewhere to keep it.  */
static UnpackedKeyType gRecord;

static void KeyEditForm_Save(FormPtr frm);
static Boolean KeyEditForm_IsDirty(FormPtr);
static void KeyEditForm_UpdateScrollbar(void);
static void KeyEditForm_Page(int offset);
static Boolean KeyEditForm_DeleteKey(Boolean saveBackup);

static Boolean keyDeleted;

// ======================================================================
// Key edit form

/* Here's one possible way to make storing these fields a bit
 * simpler: keep a struct in memory that holds the handles all the
 * fields are using to edit.  Fill the struct as records are read in,
 * and use it to calculate lengths and read values when writing out
 * without having to repeatedly interrogate the GUI fields.  We have
 * to cope specially with fields which are null and created by the
 * GUI, and also somehow check for dirty fields or whether the whole
 * record is empty and should be deleted.  */

/* When we open a record for editing, we copy each field into a memory
 * chunk of its own so that the fields can resize them as necessary.
 *
 * If we're creating a new record, we don't need to do anything: the
 * fields can allocate their own working space and we will read out of
 * it if we save the record.
 *
 * When we save the record, we concatenate all the field chunks into a
 * record, and write that out.  The field chunks are not free at that
 * point, because the gui field objects will free them when they are
 * freed themselves.
 *
 * If the user cancels, we don't need to do anything except go back to
 * the list view: the fields will deallocate their storage.
 *
 * All of the database interaction is meant to support adding
 * encryption of records at a later stage.  This mostly means that we
 * have to be able to use temporary buffers and not access the
 * database itself when packing and unpacking. */


/* Set the text in the "set date" popup trigger to match the date in
 * the record. */
static void KeyEditForm_SetDateTrigger(ControlPtr triggerPtr,
				       UnpackedKeyType *u)
{
    static Char dateBuf[dateStringLength];
    DateFormatType fmt;
    int		year, month, day;
    
    fmt = (DateFormatType) PrefGetPreference(prefLongDateFormat);

    /* DateToAscii doesn't cope well if the date is unreasonable, so we
     * filter it a bit. */
    year = limit(kYearMin, u->lastChange.year + 1904, kYearMax);
    month = limit(1, u->lastChange.month, 12);
    day = limit(1, u->lastChange.day, 31);
    
    DateToAscii(month, day, year, fmt, dateBuf);
    CtlSetLabel(triggerPtr, dateBuf);
}


/* Update the form title to reflect the current record.  If this is a
 * new record, it will be something like "New Record".  If it's an
 * existing record, it will be something like "Record 4 of 42". */
static void KeyEditForm_SetTitle(FormPtr frm) {
    Char * titleTemplate;
    static Char * gKeyFormTitle = 0;
    UInt16 pos, total;
    UInt16 len;

    if (gKeyFormTitle)
	MemPtrFree(gKeyFormTitle);

    if (gKeyRecordIndex != kNoRecord) {
	pos = gKeyRecordIndex + 1;
	total = DmNumRecordsInCategory(gKeyDB, dmAllCategories);
	
	titleTemplate = MemHandleLock(DmGetResource(strRsc, TitleTemplateStr));
	ErrFatalDisplayIf(!titleTemplate, "no titleTemplate");
	
	// Calculate length, remembering that we're going to replace
	// two two-character variables with integers that can be up to
	// 6 characters long.
	len = StrLen(titleTemplate) - 4 + 6 + 6 + 1;

	gKeyFormTitle = MemPtrNew(len);
	ErrFatalDisplayIf(!gKeyFormTitle, "couldn't allocate memory for title");
	
	StrPrintF(gKeyFormTitle, titleTemplate, pos, total);
	MemPtrUnlock(titleTemplate);
    } else {
	titleTemplate = MemHandleLock(DmGetResource(strRsc, EmptyTitleStr));
	gKeyFormTitle = MemPtrNew(StrLen(titleTemplate) + 1);
	ErrFatalDisplayIf(!gKeyFormTitle, "couldn't allocate memory for title");
	StrCopy(gKeyFormTitle, titleTemplate);
	MemPtrUnlock(titleTemplate);	
    }

    FrmCopyTitle(frm, gKeyFormTitle);
}


static void KeyEditForm_FromUnpacked(FormPtr frm, UnpackedKeyType *u) {
    FldSetTextHandle(UI_GetObjectByID(frm, KeyNameField),
		     (MemHandle) u->nameHandle);
    FldSetTextHandle(UI_GetObjectByID(frm, AccountField),
		     (MemHandle) u->acctHandle);
    FldSetTextHandle(UI_GetObjectByID(frm, PasswordField),
		     (MemHandle) u->passwdHandle);
    FldSetTextHandle(UI_GetObjectByID(frm, NotesField),
		     (MemHandle) u->notesHandle);
    KeyEditForm_SetDateTrigger(UI_GetObjectByID(frm, DateTrigger), u);
}


static void KeyEditForm_ToUnpacked(FormPtr frm, UnpackedKeyType *u) {
    FieldPtr fld;

    fld = UI_GetObjectByID(frm, KeyNameField);
    u->nameHandle = (MemHandle) FldGetTextHandle(fld);
    u->nameLen = FldGetTextLength(fld);
    
    fld = UI_GetObjectByID(frm, AccountField);
    u->acctHandle = (MemHandle) FldGetTextHandle(fld);
    u->acctLen = FldGetTextLength(fld);
    
    fld = UI_GetObjectByID(frm, PasswordField);
    u->passwdHandle = (MemHandle) FldGetTextHandle(fld);
    u->passwdLen = FldGetTextLength(fld);
    
    fld = UI_GetObjectByID(frm, NotesField);
    u->notesHandle = (MemHandle) FldGetTextHandle(fld);
    u->notesLen = FldGetTextLength(fld);

    // date is stored in the struct when it is edited
}


// If we're editing an existing record, then open it and use it to
// fill the form.
static void KeyEditForm_Load(FormPtr frm) {
    MemHandle	record = 0;
    Char *	recPtr;
    FormPtr	busyForm;

    // Open r/o
    record = DmQueryRecord(gKeyDB, gKeyRecordIndex);
    ErrNonFatalDisplayIf(!record, "coudn't query record");
    recPtr = MemHandleLock(record);
    ErrNonFatalDisplayIf(!recPtr, "couldn't lock record");
    
    busyForm = FrmInitForm(BusyDecryptForm);
    FrmDrawForm(busyForm);

    KeyRecord_Unpack(record, &gRecord, gRecordKey);
    MemHandleUnlock(record);
    KeyRecord_GetCategory(gKeyRecordIndex, &gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);
    FrmSetActiveForm(frm);

    KeyEditForm_FromUnpacked(frm, &gRecord);
    KeyEditForm_UpdateScrollbar();
}


/* Save the record if any fields are dirty, and also update
 * gRecord from the field values. */
static void KeyEditForm_MaybeSave(void) {
    FormPtr frm;

    if (keyDeleted)
	return;
    
    // TODO: Delete record if all fields empty?
    frm = FrmGetActiveForm();
    KeyEditForm_ToUnpacked(frm, &gRecord);

    if (KeyEditForm_IsDirty(frm))
	KeyEditForm_Save(frm);
}


/* Save values from the field into the database, after taking them
 * through an unpacked struct into encrypted form.
 *
 * Note that we're not *necessarily* leaving the form or even the
 * record at this point: pressing the Page buttons saves the record
 * too. */
static void KeyEditForm_Save(FormPtr frm) {
    FormPtr busyForm;
    Char * name;

    busyForm = FrmInitForm(BusyEncryptForm);
    FrmDrawForm(busyForm);

    // Pull out name to use in resorting
    if (gRecord.nameHandle)
	name = MemHandleLock(gRecord.nameHandle);
    else
	name = 0;

    if (gKeyRecordIndex == kNoRecord) {
	KeyRecord_SaveNew(&gRecord, name);
    } else {
	KeyRecord_Update(&gRecord, gKeyRecordIndex);
	KeyRecord_Reposition(name, &gKeyRecordIndex);
    }

    if (name)
	MemPtrUnlock(name);				 

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);

    // Reset title because we may have changed position
    // (but this is not necessary because we're about to leave!)
    KeyEditForm_SetTitle(frm);
    FrmSetActiveForm(frm);
}


/* Check if any fields are dirty, i.e. have been modified by the
 * user. */
static Boolean KeyEditForm_IsDirty(FormPtr frm) {
    FieldPtr fld;

    if (gRecord.categoryDirty)
	return true;

    if (gRecord.lastChangeDirty)
	return true;
    
    fld = UI_GetObjectByID(frm, KeyNameField);
    if (FldDirty(fld))
	return true;
    
    fld = UI_GetObjectByID(frm, AccountField);
    if (FldDirty(fld))
	return true;
    
    fld = UI_GetObjectByID(frm, PasswordField);
    if (FldDirty(fld))
	return true;
    
    fld = UI_GetObjectByID(frm, NotesField);
    if (FldDirty(fld))
	return true;

    return false;
}



static void KeyEditForm_New(void) {
    // Nothing to do, fields can allocate their own memory
    gRecord.lastChangeDirty = false;
    DateSecondsToDate(TimGetSeconds(), &gRecord.lastChange);
    KeyEditForm_SetDateTrigger(UI_ObjectFromActiveForm(DateTrigger),
			       &gRecord);
}



static void KeyEditForm_OpenRecord(void) {
    FieldPtr fld;
    FormPtr frm = FrmGetActiveForm();
    FieldAttrType attr;

    if (gKeyRecordIndex != kNoRecord) 
	KeyEditForm_Load(frm);
    else
	KeyEditForm_New();

    fld = UI_GetObjectByID(frm, NotesField);

    FldGetAttributes(fld, &attr);
    attr.hasScrollBar = true;
    FldSetAttributes(fld, &attr);
    
    keyDeleted = false;

    KeyEditForm_SetTitle(frm);
    FrmSetFocus(frm, FrmGetObjectIndex(frm, KeyNameField));
}


static void KeyEditForm_Update(int UNUSED(updateCode)) {
    Category_UpdateName(FrmGetActiveForm(), gRecord.category);
    FrmDrawForm(FrmGetActiveForm());
}


static void KeyEditForm_FormOpen(void) {
    KeyEditForm_OpenRecord();
    KeyEditForm_Update(updateCategory);
}


static void KeyEditForm_Done(void) {
    FrmGotoForm(ListForm);
}


static void KeyEditForm_ChooseDate(void) {
    Boolean ok;
    Int16 year, month, day;
    DatePtr date = &gRecord.lastChange;

    /* Limit to protect against SelectDay aborting. */
    year = limit(kYearMin, date->year + 1904, kYearMax);
    month = limit(1, date->month, 12);
    day = limit(1, date->day, 31);
    
    ok = SelectDay(selectDayByDay,
		   &month,
		   &day,
		   &year,
		   "Choose Date");
    if (ok) {
	ControlPtr triggerPtr;

	date->year = year - 1904;
	date->month = month;
	date->day = day;
	gRecord.lastChangeDirty = true;
	
	triggerPtr = UI_ObjectFromActiveForm(DateTrigger);
	KeyEditForm_SetDateTrigger(triggerPtr, &gRecord);
    }
}


/* Delete the record if the user is sure that's what they want. */
static Boolean KeyEditForm_MaybeDeleteKey(void) {
    // TODO: Check if the record is empty; if it is delete without
    // seeking confirmation.
    UInt16 buttonHit;
    FormPtr alert;
    Boolean saveBackup = false;

    alert = FrmInitForm(ConfirmDeleteForm);
    // TODO: Set and read archive button
    buttonHit = FrmDoDialog(alert);
    saveBackup = CtlGetValue(UI_GetObjectByID(alert, SaveArchiveCheck));
    FrmDeleteForm(alert);

    if (buttonHit == CancelBtn)
	return false;

    return KeyEditForm_DeleteKey(saveBackup);
}


static Boolean KeyEditForm_DeleteKey(Boolean saveBackup) {
    Boolean isNewRecord;
    FormPtr frm = FrmGetActiveForm();
    UnpackedKeyType unpacked;
    
    // Unpack and obliterate values so they're not left in memory.
    KeyEditForm_ToUnpacked(frm, &unpacked);
#ifdef ENABLE_OBLITERATE
    UnpackedKey_Obliterate(&unpacked);
#endif

    keyDeleted = true;

    isNewRecord = (gKeyRecordIndex == kNoRecord);

    if (isNewRecord) {
	// just quit without saving
	return true;
    } else if (saveBackup)
	DmArchiveRecord(gKeyDB, gKeyRecordIndex);
    else {
	DmDeleteRecord(gKeyDB, gKeyRecordIndex);
	// Move to the end
	DmMoveRecord(gKeyDB, gKeyRecordIndex, DmNumRecords(gKeyDB));
    }

    return true;
}


static void KeyEditForm_Generate(void) {
    FormPtr	frm;
    MemHandle 	h;
    FieldPtr	passwdFld;

    h = Generate_Run();
    if (!h)
	return;

    frm = FrmGetActiveForm();
    passwdFld = UI_GetObjectByID(frm, PasswordField);
    FldFreeMemory(passwdFld);
    FldSetTextHandle(passwdFld, (MemHandle) h);
    FldSetDirty(passwdFld, true);
    FldDrawField(passwdFld);
}


static Boolean KeyEditForm_HandleMenuEvent(EventPtr event) {
    switch (event->data.menu.itemID) {
    case HelpCmd:
	FrmHelp(KeyEditHelp);
	return true;
	
    case DeleteKeyCmd:
	if (KeyEditForm_MaybeDeleteKey())
	    FrmGotoForm(ListForm);
	return true;

    case GenerateCmd:
	KeyEditForm_Generate();
	return true;

    case ExportMemoCmd:
	/* As a side effect, MaybeSave commits the changes into
           gRecord. */
	KeyEditForm_MaybeSave();
	ExportKey(&gRecord);
	return true;
	
    default:
	return false;
    }
}


static void KeyEditForm_UpdateScrollbar(void) {
    UInt16 textHeight, fieldHeight, maxValue, scrollPos;

    FieldPtr fld;
    ScrollBarPtr bar;

    fld = UI_ObjectFromActiveForm(NotesField);
    bar = UI_ObjectFromActiveForm(NotesScrollbar);

    FldGetScrollValues(fld, &scrollPos, &textHeight, &fieldHeight);

    if (textHeight > fieldHeight)
	maxValue = textHeight - fieldHeight;
    else if (scrollPos)
	maxValue = scrollPos;
    else
	maxValue = 0;

    SclSetScrollBar(bar, scrollPos, 0, maxValue, fieldHeight-1);
}


static void KeyEditForm_Scroll(EventPtr event) {
    ScrollBarPtr scl;
    Int32 lines;
    WinDirectionType direction;
    
    scl = UI_ObjectFromActiveForm(NotesScrollbar);

    lines = event->data.sclExit.newValue - event->data.sclExit.value;

    if (lines < 0) {
	lines = -lines;
	direction = winUp;
    } else {
	direction = winDown;
    }
    
    FldScrollField(UI_ObjectFromActiveForm(NotesField),
		   lines, direction);
}


static void KeyEditForm_Page(int offset) {
    UInt16 numRecs;

    if (gKeyRecordIndex == kNoRecord)
	return;
    
    KeyEditForm_MaybeSave();

    /* TODO: Seek in this category! */

    numRecs = DmNumRecordsInCategory(gKeyDB, dmAllCategories);

    if ((gKeyRecordIndex == 0  &&  offset == -1)
	|| (gKeyRecordIndex + offset == numRecs))
	return;

    gKeyRecordIndex += offset;
    KeyEditForm_OpenRecord();
    KeyEditForm_Update(updateCategory);
}


static Boolean KeyEditForm_Arrow(int dir) {
    FormPtr frm;
    UInt16 activeIdx;
    UInt16 activeId, nextId;
    UInt16	i;
    
    static const UInt16 idLinks[] = {
	0, KeyNameField, AccountField, PasswordField, NotesField, -1
    };

    frm = FrmGetActiveForm();
    activeIdx = FrmGetFocus(frm);
    activeId = FrmGetObjectId(frm, activeIdx);

    if (!activeId)
	return false;

    /* Otherwise, look for this field and work out where to go next. */
    for (i = 0; ; i++) {
	if (idLinks[i] == (UInt16) -1)
	    return false;

	if (idLinks[i] == activeId) {
	    nextId = idLinks[i + dir];
	    if (nextId == 0  ||  nextId == (UInt16) -1)
		return false;
	    FrmSetFocus(frm, FrmGetObjectIndex(frm, nextId));
	    return true;
	}
    }

    return true;
}


static Boolean KeyEditForm_HandleKeyDownEvent(EventPtr event) {
    const int chr = event->data.keyDown.chr;
    
    switch (chr) {
    case pageUpChr:
    case pageDownChr:
	KeyEditForm_Page(chr == pageDownChr ? +1 : -1);
	return true;

    case nextFieldChr:
    case prevFieldChr:
	return KeyEditForm_Arrow(chr == nextFieldChr ? +1 : -1);

    default:
	return false;
    }
}


static void KeyEditForm_CategorySelected(void) {
    gRecord.categoryDirty = Category_Selected(&gRecord.category, false);
    if (gPrefs.category != dmAllCategories) {
	gPrefs.category = gRecord.category;
    }
}


Boolean KeyEditForm_HandleEvent(EventPtr event) {
    Boolean result = false;
    
    switch (event->eType) {
    case ctlSelectEvent:
	switch (event->data.ctlSelect.controlID) {
	case DateTrigger:
	    KeyEditForm_ChooseDate();
	    result = true;
	    break;
	case DoneBtn:
	    KeyEditForm_Done();
	    result = true;
	    break;
	case CategoryTrigger:
	    KeyEditForm_CategorySelected();
	    result = true;
	    break;
	}
	break;

    case fldChangedEvent:
	KeyEditForm_UpdateScrollbar();
	result = true;
	break;

    case frmOpenEvent:
	KeyEditForm_FormOpen();
	result = true;
	break;

    case frmUpdateEvent:
	KeyEditForm_Update(~0);
	result = true;
	break;

    case frmCloseEvent:
	KeyEditForm_MaybeSave();
#ifdef ENABLE_OBLITERATE
	UnpackedKey_Obliterate(&gRecord);
#endif
	result = false;
	break;

    case keyDownEvent:
	result = KeyEditForm_HandleKeyDownEvent(event);
	break;

    case menuEvent:
	if (!Common_HandleMenuEvent(event)
	    && !KeyEditForm_HandleMenuEvent(event))
	    App_NotImplemented();
	result = true;
	break;

    case sclRepeatEvent:
    case sclExitEvent:
	KeyEditForm_Scroll(event);
	break;

    default:
    }
    return result;
}
