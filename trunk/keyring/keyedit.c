/* -*- c-indentation-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*-
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
#include "crypto.h"
#include "snib.h"
#include "pack.h"
#include "unpack.h"
#include "auto.h"


/* TODO: Show position and do paging within category -- is this working now?
 *
 * TODO: If we can, page down in the notes field before going to the
 * next record.  Similarly backwards.
 *
 * TODO: Be more careful about not saving unless actually modified, as
 * this can save a lot of time.  I think we handle all the obvious
 * cases now.
 */


/* This keeps an unpacked version of the record currently being
 * edited.  They're periodically sync'd up; e.g. just before saving.
 *
 * It's a bit unfortunate to keep it in a global like this, but the
 * problem is that the date isn't stored by the GUI control, so we
 * need somewhere to keep it.  */
static UnpackedKeyType gRecord;

static void KeyEditForm_Save(void);
static void KeyEditForm_UpdateScrollbar(void);
static void KeyEditForm_Page(int offset);
static Boolean KeyEditForm_DeleteKey(Boolean saveBackup);
static Boolean KeyEditForm_IsDirty(void);
static void KeyEditForm_MarkClean(void);

static Boolean keyDeleted;

// If the form is active, all these are valid.
static FieldPtr f_NotesFld, f_KeyNameFld, f_AcctFld, f_PasswdFld;
static ScrollBarPtr f_NotesScrollBar;
static FormPtr f_KeyEditForm;

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



/* Update the form title to reflect the current record.  If this is a
 * new record, it will be something like "New Record".  If it's an
 * existing record, it will be something like "Record 4 of 42". */
static void KeyEditForm_UpdateTitle(void)
{
    Char * titleTemplate;
    static Char * f_KeyFormTitle = 0;
    UInt16 pos, total;
    UInt16 len, reserved;

    if (f_KeyFormTitle)
        MemPtrFree(f_KeyFormTitle);

    if (gKeyPosition != kNoRecord) {
        reserved = Keys_IdxOffsetReserved();
        pos = gKeyPosition + 1 - reserved;
        total = DmNumRecordsInCategory(gKeyDB, gPrefs.category) - reserved;
        
        titleTemplate = MemHandleLock(DmGetResource(strRsc, TitleTemplateStr));
        ErrFatalDisplayIf(!titleTemplate, "no titleTemplate");
        
        // Calculate length, remembering that we're going to replace
        // two two-character variables with integers that can be up to
        // 6 characters long.
        len = StrLen(titleTemplate) - 4 + 6 + 6 + 1;

        if (!(f_KeyFormTitle = MemPtrNew(len)))
            goto failOut;
        
        StrPrintF(f_KeyFormTitle, titleTemplate, pos, total);
        MemPtrUnlock(titleTemplate);
    } else {
        titleTemplate = MemHandleLock(DmGetResource(strRsc, EmptyTitleStr));
        if (!(f_KeyFormTitle = MemPtrNew(StrLen(titleTemplate) + 1)))
            goto failOut;
        
        StrCopy(f_KeyFormTitle, titleTemplate);
        MemPtrUnlock(titleTemplate);    
    }

    FrmCopyTitle(f_KeyEditForm, f_KeyFormTitle);
    return;

 failOut:
    FrmAlert(OutOfMemoryAlert);
    return;
}


static void KeyEditForm_FromUnpacked(FormPtr frm, UnpackedKeyType *u) {
    ErrFatalDisplayIf(frm != f_KeyEditForm, "fraudulent FormPtr");
    FldSetTextHandle(f_KeyNameFld, (MemHandle) u->nameHandle);
    FldSetTextHandle(f_AcctFld, (MemHandle) u->acctHandle);
    FldSetTextHandle(f_PasswdFld, (MemHandle) u->passwdHandle);
    FldSetTextHandle(f_NotesFld, (MemHandle) u->notesHandle);
}


/*
 * Wipe out all the fields on this form.
 */
static void KeyEditForm_Clear(void) {
    FldDelete(f_KeyNameFld, 0, (UInt16) -1);
    FldDelete(f_AcctFld, 0, (UInt16) -1);
    FldDelete(f_PasswdFld, 0, (UInt16) -1);
    FldDelete(f_NotesFld, 0, (UInt16) -1);
}


static void KeyEditForm_ToUnpacked(UnpackedKeyType *u) {
    FieldPtr fld;

    u->nameHandle = (MemHandle) FldGetTextHandle(f_KeyNameFld);
    u->nameLen = FldGetTextLength(f_KeyNameFld);
    
    fld = f_AcctFld;
    u->acctHandle = (MemHandle) FldGetTextHandle(fld);
    u->acctLen = FldGetTextLength(fld);
    
    fld = f_PasswdFld;
    u->passwdHandle = (MemHandle) FldGetTextHandle(fld);
    u->passwdLen = FldGetTextLength(fld);
    
    fld = f_NotesFld;
    u->notesHandle = (MemHandle) FldGetTextHandle(fld);
    u->notesLen = FldGetTextLength(fld);

    // date is stored in the struct when it is edited
}


static void KeyEditForm_Done(void) {
    FrmGotoForm(ListForm);
}

/*  static Err KeyEditForm_Wakeup(SysNotifyParamType *np) { */
/*      if(np->notifyType == sysNotifyLateWakeupEvent) { */
/*      SysNotifyUnregister(gKeyDBCardNo, */
/*                          gKeyDBID, */
/*                          sysNotifyLateWakeupEvent, */
/*                          sysNotifyNormalPriority); */
/*      KeyEditForm_Done(); */
/*      } */
/*      return 0; */
/*  } */


/*
 * Fill in the current KeyEdit form with data from the record
 * [gKeyRecordIndex].  We have to decrypt and unpack all the data.
 * gRecordKey already contains the decrypted record key.
 */
static void KeyEditForm_Load(void)
{
    MemHandle   record = 0;
    Char *      recPtr;
    FormPtr     busyForm;

    // Open r/o
    record = DmQueryRecord(gKeyDB, gKeyRecordIndex);
    ErrNonFatalDisplayIf(!record, "coudn't query record");
    recPtr = MemHandleLock(record);
    ErrNonFatalDisplayIf(!recPtr, "couldn't lock record");
    
    busyForm = FrmInitForm(BusyDecryptForm);
    FrmDrawForm(busyForm);

    Keys_Unpack(record, &gRecord);
    MemHandleUnlock(record);
    KeyRecord_GetCategory(gKeyRecordIndex, &gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);
    FrmSetActiveForm(f_KeyEditForm);

    KeyEditForm_FromUnpacked(f_KeyEditForm, &gRecord);
    KeyEditForm_UpdateScrollbar();

    /* NotifyRegister is not present in 3.0.  We need to check for
     * (sysFtrCreator, sysFtrNumNotifyMgrVersion) to see if we can
     * call this.  It might be better to set an alarm to lock after
     * the specified time instead. */
/*      SysNotifyRegister(gKeyDBCardNo, */
/*                    gKeyDBID, */
/*                    sysNotifyLateWakeupEvent, */
/*                    KeyEditForm_Wakeup, */
/*                    sysNotifyNormalPriority, */
/*                    NULL); */
}


/* Save the record if any fields are dirty, and also update
 * gRecord from the field values. */
static void KeyEditForm_MaybeSave(void) {
    if (keyDeleted)
        return;
    
    // TODO: Delete record if all fields empty?
    KeyEditForm_ToUnpacked(&gRecord);

    if (KeyEditForm_IsDirty()) {
        KeyEditForm_Save();
        KeyEditForm_MarkClean();
    }
}


/* Save values from the field into the database, after taking them
 * through an unpacked struct into encrypted form.  The fields must
 * already be in gRecord.
 *
 * Note that we're not *necessarily* leaving the form or even the
 * record at this point: pressing the Page buttons saves the record
 * too. */
static void KeyEditForm_Save(void) 
{
    FormPtr busyForm;

    busyForm = FrmInitForm(BusyEncryptForm);
    FrmDrawForm(busyForm);

    Keys_SaveRecord(&gRecord, &gKeyRecordIndex);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);

    // Reset title because we may have changed position
    // (but this is not necessary because we're about to leave!)
    KeyEditForm_UpdateTitle();
    FrmSetActiveForm(f_KeyEditForm);
}


static void KeyEditForm_UpdateCategory(void) {
    Category_UpdateName(f_KeyEditForm, gRecord.category);
}


static void KeyEditForm_UpdateAll(void)
{
    KeyEditForm_UpdateCategory();
    KeyEditForm_UpdateTitle();
    FrmDrawForm(f_KeyEditForm);
}


/*
 * Throw away all the changes to the current key.  If this is an
 * existing key, reload it from the database.  If this is a new key,
 * go back to a blank form.
 */
static void Keys_UndoAll(void) {
    if (gKeyRecordIndex == kNoRecord) {
        KeyEditForm_Clear();
    } else {
        KeyEditForm_Load();
    }
    /* TODO: Put the category back to what it was when we entered. */
    KeyEditForm_UpdateAll();
}


/*
 * Mark all fields as clean; called just after we save
 */
static void KeyEditForm_MarkClean(void)
{
    FldSetDirty(f_KeyNameFld, false);
    FldSetDirty(f_PasswdFld, false);
    FldSetDirty(f_AcctFld, false);
    FldSetDirty(f_NotesFld, false);
}


/* Check if any fields are dirty, i.e. have been modified by the
 * user. */
static Boolean KeyEditForm_IsDirty(void)
{
    if (gRecord.categoryDirty
        || FldDirty(f_KeyNameFld)
        || FldDirty(f_PasswdFld)
        || FldDirty(f_AcctFld)
        || FldDirty(f_NotesFld))
     return true;

    return false;
}



static void KeyEditForm_New(void) {
    /* All of the text fields allocate their own memory as they go.
     * The others we have to set up by hand. */
    gRecord.categoryDirty = false;
    if (gPrefs.category == dmAllCategories)
        gRecord.category = dmUnfiledCategory;
    else
        gRecord.category = gPrefs.category;
}



static void KeyEditForm_OpenRecord(void) {
    FieldAttrType attr;

    if (gKeyRecordIndex != kNoRecord) 
        KeyEditForm_Load();
    else
        KeyEditForm_New();

    FldGetAttributes(f_NotesFld, &attr);
    attr.hasScrollBar = true;
    FldSetAttributes(f_NotesFld, &attr);
    
    keyDeleted = false;

    FrmSetFocus(f_KeyEditForm,
                FrmGetObjectIndex(f_KeyEditForm, ID_KeyNameField));
    KeyEditForm_UpdateAll();
}


static void KeyEditForm_GetFields(void)
{
    f_KeyEditForm = FrmGetActiveForm();
    f_KeyNameFld = UI_GetObjectByID(f_KeyEditForm, ID_KeyNameField),
    f_NotesFld = UI_GetObjectByID(f_KeyEditForm, ID_NotesField);
    f_AcctFld = UI_GetObjectByID(f_KeyEditForm, AccountField);
    f_PasswdFld = UI_GetObjectByID(f_KeyEditForm, PasswordField);
    f_NotesScrollBar = UI_GetObjectByID(f_KeyEditForm, NotesScrollbar);
}


static void KeyEditForm_FormOpen(void) {
    KeyEditForm_GetFields();
    KeyEditForm_OpenRecord();
    KeyEditForm_UpdateAll();
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
    UnpackedKeyType unpacked;
    
    // Unpack and obliterate values so they're not left in memory.
    KeyEditForm_ToUnpacked(&unpacked);

    keyDeleted = true;

    isNewRecord = (gKeyRecordIndex == kNoRecord);

    if (isNewRecord) {
        // just quit without saving
        return true;
    } else if (saveBackup) {
        DmArchiveRecord(gKeyDB, gKeyRecordIndex);
    } else {
        DmDeleteRecord(gKeyDB, gKeyRecordIndex);
        // Move to the end
        DmMoveRecord(gKeyDB, gKeyRecordIndex, DmNumRecords(gKeyDB));
    }

    return true;
}


static void KeyEditForm_Generate(void) {
    FormPtr     frm;
    MemHandle   h;
    FieldPtr    passwdFld;

    h = Generate_Run();
    if (!h)
        return;

    frm = f_KeyEditForm;
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

    case ID_UndoAllCmd:
        Keys_UndoAll();
        return true;
        
    default:
        return false;
    }
}


static void KeyEditForm_UpdateScrollbar(void) {
    UInt16 textHeight, fieldHeight, maxValue, scrollPos;

    FldGetScrollValues(f_NotesFld, &scrollPos, &textHeight, &fieldHeight);

    if (textHeight > fieldHeight)
        maxValue = textHeight - fieldHeight;
    else if (scrollPos)
        maxValue = scrollPos;
    else
        maxValue = 0;

    SclSetScrollBar(f_NotesScrollBar, scrollPos, 0, maxValue, fieldHeight-1);
}


static void KeyEditForm_Scroll(EventPtr event) {
    Int32 lines;
    WinDirectionType direction;
    
    lines = event->data.sclExit.newValue - event->data.sclExit.value;

    if (lines < 0) {
        lines = -lines;
        direction = winUp;
    } else {
        direction = winDown;
    }
    
    FldScrollField(f_NotesFld, lines, direction);
}


static void KeyEditForm_Page(int offset) {
    UInt16 numRecs;
    UInt16 reserved;

    if (gKeyRecordIndex == kNoRecord) {
        /* You can't page while you're editing a new record. */
        SndPlaySystemSound(sndWarning);
        return;
    }
    
    KeyEditForm_MaybeSave();

    numRecs = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
    reserved = (UInt16) Keys_IdxOffsetReserved();

    if ((gKeyPosition <= reserved  &&  offset == -1)
        || (gKeyPosition + offset == numRecs)) {
        /* Bumped into the end */
        SndPlaySystemSound(sndWarning);
        return;
    }

    gKeyPosition += offset;
    gKeyRecordIndex = 0;
    DmSeekRecordInCategory(gKeyDB, &gKeyRecordIndex, gKeyPosition,
                           dmSeekForward, gPrefs.category);
    
    KeyEditForm_OpenRecord();
}


static Boolean KeyEditForm_Arrow(int dir) {
    FormPtr frm;
    UInt16 activeIdx;
    UInt16 activeId, nextId;
    UInt16      i;
    
    static const UInt16 idLinks[] = {
        0, ID_KeyNameField, AccountField, PasswordField, ID_NotesField, -1
    };

    frm = f_KeyEditForm;
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
    if (gRecord.categoryDirty)
        KeyEditForm_UpdateCategory();
}


Boolean KeyEditForm_HandleEvent(EventPtr event) {
    Boolean result = false;
    
    switch (event->eType) {
    case ctlSelectEvent:
        switch (event->data.ctlSelect.controlID) {
        case DoneBtn:
            KeyEditForm_Done();
            result = true;
            break;
        case CategoryTrigger:
            KeyEditForm_CategorySelected();
            return true;
        }
        break;

    case fldChangedEvent:
        if (event->data.fldChanged.fieldID == ID_NotesField) {
            KeyEditForm_UpdateScrollbar();
            result = true;
        }
        break;

    case frmOpenEvent:
        KeyEditForm_FormOpen();
        result = true;
        break;

    case frmCloseEvent:
        KeyEditForm_MaybeSave();
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
