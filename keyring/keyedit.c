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
 *
 * TODO: Resort the database when editing is finished.  It's probably
 * simplest not to sort until returning to the list.
 *
 * FIXME: Position in the form title is wrong after changing
 * categories.  Do we want to stay in the originally selected category?
 *
 * TODO: When the category is changed, don't re-encrypt the record.
 * Instead just move it into the new category and update the position
 * indicator.
 *
 * TODO: Perhaps close the list form while we're in the edit form?
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
static Boolean KeyEditForm_IsDirty(void);
static Boolean KeyEditForm_IsEmpty(void);
static void KeyEditForm_MarkClean(void);
static void KeyEditForm_DeleteKey(Boolean saveBackup);

static Boolean keyDeleted;

// If the form is active, all these are valid.
static FieldPtr f_NotesFld, f_KeyNameFld, f_AcctFld, f_PasswdFld;
static ScrollBarPtr f_NotesScrollBar;
static FormPtr f_KeyEditForm;

/* Index of the current record in the database as a whole. */
UInt16		gKeyRecordIndex = kNoRecord;

/* Index of the current record within the currently-displayed
 * category. */
UInt16		gKeyPosition = kNoRecord;


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
 * When the user creates a new record, we allocate it immediately on
 * entering the form: this fits well with the user interface
 * abstraction, which is that a new blank record is allocated at that
 * point.  It also means that all the rest of the code just has to
 * deal with a single case of editing an existing record.  To get rid
 * of the record, the user must choose to delete it or (equivalently)
 * leave all the fields empty. */


/* Update the form title to reflect the current record.  If this is a
 * new record, it will be something like "New Record".  If it's an
 * existing record, it will be something like "Record 4 of 42".
 *
 * - I haven't isolated the next as it is sometimes intermittent: a
 * bus error results after selecting a record from the list then
 * pressing Page Up key.  I think it's somewhere in
 * KeyEditForm_SetTitle(). -- Dell */
static void KeyEditForm_UpdateTitle(void)
{
    Char * titleTemplate;
    static Char * f_KeyFormTitle = 0;
    UInt16 pos, total;
    UInt16 len;

    if (f_KeyFormTitle)
        MemPtrFree(f_KeyFormTitle);

    if (gKeyRecordIndex != kNoRecord) {
        pos = gKeyPosition + 1;
        total = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
        
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


static void KeyEditForm_FromUnpacked(void) {
    FldSetTextHandle(f_KeyNameFld, (MemHandle) gRecord.nameHandle);
    FldSetTextHandle(f_AcctFld, (MemHandle) gRecord.acctHandle);
    FldSetTextHandle(f_PasswdFld, (MemHandle) gRecord.passwdHandle);
    FldSetTextHandle(f_NotesFld, (MemHandle) gRecord.notesHandle);
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

    KeyEditForm_FromUnpacked();
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
static void KeyEditForm_Commit(void) {
    if (keyDeleted)
        return;

    if (KeyEditForm_IsEmpty()) {
        KeyEditForm_DeleteKey(false); /* no backup */
        KeyEditForm_MarkClean();
    } else if (KeyEditForm_IsDirty()) {
        // TODO: Delete record if all fields empty?
        KeyEditForm_ToUnpacked(&gRecord);

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
    Key_SetCategory(gKeyRecordIndex, gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);

    // Reset title because we may have changed position (but this may
    // not be necessary because we're about to leave!)

    /* - It'll give a bus error after creating a new entry. (My
       experience shows that a bus error is usually a result of a bad
       pointer).  The bus error comes from KeyEdit.c, procedure
       KeyEditForm_Save, last two lines, which in your remarks say are
       unnecessary.  Removing these two lines eliminates the bus
       error. */
    KeyEditForm_UpdateTitle();
    FrmSetActiveForm(f_KeyEditForm);
}


/* Update the category popuptrigger to show the current record's
 * category name. */
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
        /* TODO: Check that this works OK if the record is
         * newly-allocated and zero length. */
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
    return (FldDirty(f_KeyNameFld) || FldDirty(f_PasswdFld)
            || FldDirty(f_AcctFld) || FldDirty(f_NotesFld));
}


/* Check if all fields are empty.  If so, when leaving we will discard
 * the record rather than saving it. */
static Boolean KeyEditForm_IsEmpty(void)
{
    return !(FldGetTextLength(f_KeyNameFld) || FldGetTextLength(f_PasswdFld)
             || FldGetTextLength(f_AcctFld) || FldGetTextLength(f_NotesFld));
}


/* Called from the list form when creating a new record. */
void KeyEditForm_GotoNew(void) {
    gKeyRecordIndex = gKeyPosition = kNoRecord;
    
    FrmGotoForm(KeyEditForm);
}



void KeyEditForm_GotoRecord(UInt16 recordIdx) {
    gKeyRecordIndex = recordIdx;
    gKeyPosition = DmPositionInCategory(gKeyDB, gKeyRecordIndex, gPrefs.category);
}
        


static void KeyEditForm_New(void) {
    /* All of the text fields allocate their own memory as they go.
     * The others we have to set up by hand. */
    if (gPrefs.category == dmAllCategories)
        gRecord.category = dmUnfiledCategory;
    else
        gRecord.category = gPrefs.category;
}



static void KeyEditForm_OpenRecord(void) {
    FieldAttrType attr;

    if (gKeyRecordIndex != kNoRecord) 
        KeyEditForm_Load();
    else {
        KeyEditForm_New();
        KeyDB_CreateNew(&gKeyRecordIndex);
        /* TODO: If this fails, do something. */
    }

    gKeyPosition = DmPositionInCategory(gKeyDB, gKeyRecordIndex, gPrefs.category);

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


static void KeyEditForm_DeleteKey(Boolean saveBackup)
{
    UnpackedKeyType unpacked;
    
    // Unpack and obliterate values so they're not left in memory.
    // XXX: This sounds kind of unnecessary -- can we avoid it, since
    // we're not obliterating field data?
    KeyEditForm_ToUnpacked(&unpacked);

    // We set keyDeleted to make sure that we don't try to save this
    // record as the form closes.
    keyDeleted = true;

    if (saveBackup) {
        DmArchiveRecord(gKeyDB, gKeyRecordIndex);
    } else {
        DmDeleteRecord(gKeyDB, gKeyRecordIndex);
        // Move to the end to make the ordering of the remaining
        // records simple.
        DmMoveRecord(gKeyDB, gKeyRecordIndex, DmNumRecords(gKeyDB));
    }
}


/* Delete the record if the user is sure that's what they want.
 * Return true if deleted and we should return to the list form,
 * otherwise false. */
static Boolean KeyEditForm_MaybeDelete(void) {
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

    KeyEditForm_DeleteKey(saveBackup);

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
        if (KeyEditForm_MaybeDelete())
            FrmGotoForm(ListForm);
        return true;

    case GenerateCmd:
        KeyEditForm_Generate();
        return true;

    case ExportMemoCmd:
        /* As a side effect, write into gRecord. */
        KeyEditForm_Commit();
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


static void KeyEditForm_Dragged(EventPtr event) {
    Int32 lines = event->data.sclExit.newValue - event->data.sclExit.value;
    WinDirectionType direction;

    if (lines < 0) {
        lines = -lines;
        direction = winUp;
    } else {
        direction = winDown;
    }
    
    FldScrollField(f_NotesFld, lines, direction);
}


/*
 * Move backwards or forwards by one record.  Save and reload data if
 * necessary.  If there is no such record, or if we're inserting a new
 * record, then beep and do nothing else.
 */
static void KeyEditForm_FlipRecord(WinDirectionType dir)
{
    UInt16 numRecs;
    Int16 offset = (dir == winDown) ? +1 : -1;
    
    KeyEditForm_Commit();

    numRecs = DmNumRecordsInCategory(gKeyDB, gPrefs.category);

    if ((gKeyPosition == 0  &&  offset == -1)
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


/*
 * If possible, scroll the notes field.  Otherwise, flip forward or
 * backward by one record.
 */
static void KeyEditForm_PageButton(WinDirectionType dir)
{
    Int16 lines;
    
    if (FldScrollable(f_NotesFld, dir)) {
        lines = FldGetVisibleLines(f_NotesFld);
        FldScrollField(f_NotesFld, lines, dir);
        KeyEditForm_UpdateScrollbar();
    } else {
        KeyEditForm_FlipRecord(dir);
    }
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
        KeyEditForm_PageButton(chr == pageDownChr ? winDown : winUp);
        return true;

    case nextFieldChr:
    case prevFieldChr:
        return KeyEditForm_Arrow(chr == nextFieldChr ? +1 : -1);

    default:
        return false;
    }
}


static void KeyEditForm_CategorySelected(void) {
    Boolean categoryChanged;

    categoryChanged = Category_Selected(&gRecord.category, false);
    if (gPrefs.category != dmAllCategories) {
        gPrefs.category = gRecord.category;
    }
    if (categoryChanged) {
        KeyEditForm_UpdateCategory();
    }
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
            return true;
        }
        break;

    case frmOpenEvent:
        KeyEditForm_FormOpen();
        result = true;
        break;

    case frmCloseEvent:
        KeyEditForm_Commit();
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
        KeyEditForm_Dragged(event);
        break;

    default:
    }
    return result;
}
