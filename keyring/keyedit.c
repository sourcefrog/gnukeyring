/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 *
 * GNU Keyring -- store passwords securely on a handheld
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

#include "resource.h"
#include "keyring.h"
#include "keyedit.h"
#include "keydb.h"
#include "uiutil.h"
#include "util.h"
#include "crypto.h"
#include "generate.h"
#include "record.h"
#include "export.h"
#include "category.h"
#include "snib.h"
#include "pack.h"
#include "unpack.h"
#include "auto.h"
#include "sort.h"
#include "listform.h"
#include "passwd.h"

/*
 * TODO: Newline in single-line fields should move down one, perhaps?
 * Really this is only useful on POSE -- on the real system, people
 * can just use the next-field character.
 *
 * TODO: When flipping records, if the timeout has expired instead go
 * back to the list. 
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
static void Edit_DeleteKey(Boolean saveBackup);
static void KeyEditForm_GetFields(void);

static Boolean f_keyDiscarded;

// If the form is active, all these are valid.
static FieldPtr f_NotesFld, f_KeyNameFld, f_AcctFld, f_PasswdFld;
static ScrollBarPtr f_NotesScrollBar;
static FormPtr f_KeyEditForm;

#define k_NumFields 4
static FieldPtr f_AllFields[k_NumFields];

/* Index of the current record in the database as a whole. */
UInt16          gKeyRecordIndex = kNoRecord;

/* True if we should sort the database on leaving this form.  At the
 * moment we set this on any modification, although we could perhaps
 * be a bit more selective. */
static Boolean f_needsSort;

/* Holds the string to be copied into the title.  Must be big enough
 * to handle the largest possible expansion. */
Char f_KeyFormTitle[32];


extern Boolean g_ReadOnly;


// ======================================================================
// Key edit form

/* All of the text fields manage their own memory, including resizing
 * the allocations when required.  We fill the struct containing
 * handles as records are read in, and use it to calculate lengths and
 * read values when writing out without having to repeatedly
 * interrogate the GUI fields.  We have to cope specially with fields
 * which are null and created by the GUI, and also somehow check for
 * dirty fields or whether the whole record is empty and should be
 * deleted.  */

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
 * KeyEditForm_SetTitle(). -- dmgarner */
static void KeyEditForm_UpdateTitle(void)
{
    Char * titleTemplate;
    UInt16 pos, total;
    
    ErrNonFatalDisplayIf(gKeyRecordIndex == kNoRecord,
                         __FUNCTION__ ": no record");

    /* 1-based count */
    pos = 1 + DmPositionInCategory(gKeyDB, gKeyRecordIndex, gPrefs.category);
    total = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
        
    titleTemplate = MemHandleLock(DmGetResource(strRsc, TitleTemplateStr));
    ErrFatalDisplayIf(!titleTemplate, __FUNCTION__ ": no titleTemplate");

    StrPrintF(f_KeyFormTitle, titleTemplate, pos, total);
    MemPtrUnlock(titleTemplate);

    FrmCopyTitle(f_KeyEditForm, f_KeyFormTitle);
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
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          FldDelete(f_AllFields[i], 0, (UInt16) -1);
     }
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
    FrmSetActiveForm(busyForm);
    FrmDrawForm(busyForm);

    Keys_UnpackRecord(recPtr, &gRecord);
    MemHandleUnlock(record);
    KeyRecord_GetCategory(gKeyRecordIndex, &gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);
    FrmSetActiveForm(f_KeyEditForm);

    KeyEditForm_FromUnpacked();

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


/*
 * Save the record if any fields are dirty, and also update gRecord
 * from the field values.  If the record has been left empty, then
 * delete it rather than saving an empty record.
 */
static void KeyEditForm_Commit(void) {
    if (f_keyDiscarded)
        return;

    if (KeyEditForm_IsEmpty()) {
         Edit_DeleteKey(false); /* no backup */
         KeyEditForm_MarkClean();
    } else if (KeyEditForm_IsDirty()) {
         f_needsSort = true;
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

    FrmSetActiveForm(f_KeyEditForm);
}


/* Update the category popuptrigger to show the current record's
 * category name. */
static void KeyEditForm_UpdateCategory(void) {
    Category_UpdateName(f_KeyEditForm, gRecord.category);
}


static void KeyEditForm_UpdateAll(void)
{
    KeyEditForm_GetFields();
    KeyEditForm_UpdateCategory();
    KeyEditForm_UpdateTitle();
    KeyEditForm_UpdateScrollbar();
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
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          FldSetDirty(f_AllFields[i], false);
     }
}


/* Check if any fields are dirty, i.e. have been modified by the
 * user. */
static Boolean KeyEditForm_IsDirty(void)
{
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          if (FldDirty(f_AllFields[i]))
               return true;
     }

     return false;
}


/* Check if all fields are empty.  If so, when leaving we will discard
 * the record rather than saving it. */
static Boolean KeyEditForm_IsEmpty(void)
{
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          if (FldGetTextLength(f_KeyNameFld))
               return false;
     }

     return true;
}


/* Called from the list form when creating a new record. */
void KeyEditForm_GotoNew(void) {
    gKeyRecordIndex = kNoRecord;
    
    FrmGotoForm(KeyEditForm);
}



void KeyEditForm_GotoRecord(UInt16 recordIdx) {
    gKeyRecordIndex = recordIdx;
}
        


static void Key_SetNewRecordCategory(void)
{
    if (gPrefs.category == dmAllCategories)
        gRecord.category = dmUnfiledCategory;
    else
        gRecord.category = gPrefs.category;

    Key_SetCategory(gKeyRecordIndex, gRecord.category);
}



static void KeyEditForm_OpenRecord(void) {
    if (gKeyRecordIndex != kNoRecord) 
        KeyEditForm_Load();
    else {
        KeyDB_CreateNew(&gKeyRecordIndex);
        Key_SetNewRecordCategory();
        /* TODO: If this fails, do something. */
    }

    f_keyDiscarded = false;

    FrmSetFocus(f_KeyEditForm,
                FrmGetObjectIndex(f_KeyEditForm, ID_KeyNameField));
    KeyEditForm_UpdateAll();
}


static void KeyEditForm_GetFields(void)
{
    f_KeyEditForm = FrmGetActiveForm();

    f_AllFields[0] = f_KeyNameFld =
         UI_GetObjectByID(f_KeyEditForm, ID_KeyNameField);
    
    f_AllFields[1] = f_NotesFld = UI_GetObjectByID(f_KeyEditForm, ID_NotesField);
    f_AllFields[2] = f_AcctFld = UI_GetObjectByID(f_KeyEditForm, AccountField);
    
    f_AllFields[3] = f_PasswdFld =
         UI_GetObjectByID(f_KeyEditForm, PasswordField);
 
    f_NotesScrollBar = UI_GetObjectByID(f_KeyEditForm, NotesScrollbar);
}


/*
 * Set run-time-only attributes on fields.  This is called each time the
 * form is opened.
 */
static void Edit_PrepareFields(void)
{
    FieldAttrType attr;

    FldGetAttributes(f_NotesFld, &attr);
    attr.hasScrollBar = true;
    FldSetAttributes(f_NotesFld, &attr);

    /* If the database is read-only, apply that attribute to the
     * fields. */
    if (g_ReadOnly) {
         Int16 i;

         for (i = 0; i < k_NumFields; i++) {
              FldGetAttributes(f_AllFields[i], &attr);
              attr.editable = false;
              FldSetAttributes(f_AllFields[i], &attr);
         }              
    }
}


static void KeyEditForm_FormOpen(void) {
     f_needsSort = false;
     KeyEditForm_GetFields();
     Edit_PrepareFields();
     KeyEditForm_OpenRecord();
}


static void Edit_SortAndFollow(void) {
     UInt32 uniqueId;
     Boolean followRecord;

     /* TODO: We need to update gKeyRecordIndex as the "current"
      * record may now have a different index. */
     followRecord = (gKeyRecordIndex != kNoRecord) && !f_keyDiscarded;

     if (followRecord)
          DmRecordInfo(gKeyDB, gKeyRecordIndex, NULL, &uniqueId, NULL);

     Keys_Sort();

     if (followRecord)
          DmFindRecordByID(gKeyDB, uniqueId, &gKeyRecordIndex);
}


static void Edit_FormClose(void) {
     KeyEditForm_Commit();
     if (f_needsSort) {
          Edit_SortAndFollow();
     }

     /* This is not necessarily a reasonable index, but the list form
      * will check it before use. */
     if (f_keyDiscarded)
          f_FirstIdx = 0;
     else
          f_FirstIdx = DmPositionInCategory(gKeyDB, gKeyRecordIndex,
                                            gPrefs.category);
}


/*
 * Delete the current record, and set f_keyDiscarded.
 */
static void Edit_DeleteKey(Boolean saveBackup)
{
     /* We set f_keyDiscarded to make sure that we don't try to save this
      * record as the form closes. */
    f_keyDiscarded = true;

    /* I don't think there's any need to sort here, because nothing else
     * has moved. */

    if (saveBackup) {
        DmArchiveRecord(gKeyDB, gKeyRecordIndex);
    } else {
        DmDeleteRecord(gKeyDB, gKeyRecordIndex);
        // Move to the end to make the ordering of the remaining
        // records simple.
        DmMoveRecord(gKeyDB, gKeyRecordIndex, DmNumRecords(gKeyDB));
        // gKeyRecordIndex now refers to the next record.  That's probably OK.
    }

    gKeyRecordIndex = kNoRecord;
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

    Edit_DeleteKey(saveBackup);

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


/*
 * Export if possible.
 */
static void Edit_MaybeExport(void)
{
     if (KeyEditForm_IsEmpty()) {
          FrmAlert(alertID_ExportEmpty);
          return;
     }
     
     /* As a side effect, write into gRecord. */
     KeyEditForm_Commit();
     ExportKey(&gRecord);
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
         Edit_MaybeExport();
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
 * Open the record at the specified position in the current category.
 */
static void Edit_OpenAtPosition(Int16 pos)
{
    gKeyRecordIndex = 0;
    DmSeekRecordInCategory(gKeyDB, &gKeyRecordIndex, pos,
                           dmSeekForward, gPrefs.category);
    
    KeyEditForm_OpenRecord();
}


/*
 * Seek forwards or backwards from the current record.
 */
static void Edit_OpenAtOffset(Int16 offset)
{
     Int16 pos, dir;

     if (offset < 0) {
          pos = -offset;
          dir = dmSeekBackward;
     } else {
          pos = offset;
          dir = dmSeekForward;
     }
          
     DmSeekRecordInCategory(gKeyDB, &gKeyRecordIndex, pos, dir,
                            gPrefs.category);
    
    KeyEditForm_OpenRecord();
}     



/*
 * Move backwards or forwards by one record.  The current record
 * has been committed, which may have caused f_keyDiscarded to be
 * set.
 *
 * If the timeout has passed then we do not allow a new record to be
 * opened.  The user must either re-enter their password, or stay
 * stuck on the same record.  They can always press Done to go back to
 * the list.
 */
static void Edit_TryFlip(Int16 offset)
{
     UInt16 numRecs;
     UInt16 pos;
     
     pos = DmPositionInCategory(gKeyDB, gKeyRecordIndex, gPrefs.category);
     numRecs = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
     
     if ((pos == 0  &&  offset == -1) || (pos + offset == numRecs)) {
          /* Bumped into the end */
          SndPlaySystemSound(sndWarning);
          return;
     }

     if (!(Unlock_CheckTimeout() || UnlockForm_Run()))
          return; /* otherwise, stay on the same record. */

     KeyEditForm_Commit();

     if (f_keyDiscarded) {
          if (numRecs <= 1) {
               /* Deleted the last record in the category. */
               KeyEditForm_Done();
               return;
          }

          /* We have to do an absolute seek, because when a record is
           * discarded it is also re-ordered.  Flipping forward from a
           * discarded record stays at the same absolute position,
           * because the remaining records have just shuffled
           * forward. */
          if (offset == -1) {
               pos--;
          }
          Edit_OpenAtPosition(pos);
     } else {
          Edit_OpenAtOffset(offset);
     }
}



/*
 * If possible, scroll the notes field.  Otherwise, flip forward or
 * backward by one record.  Before flipping records, commit changes
 * and act appropriately if the record was actually discarded.
 */
static void KeyEditForm_PageButton(WinDirectionType dir)
{
    Int16 lines, offset;
    
    if (FldScrollable(f_NotesFld, dir)) {
        lines = FldGetVisibleLines(f_NotesFld);
        FldScrollField(f_NotesFld, lines, dir);
        KeyEditForm_UpdateScrollbar();
    } else {
         offset = (dir == winDown) ? +1 : -1;
         Edit_TryFlip(offset);
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
    if (categoryChanged) {
        if (gPrefs.category != dmAllCategories) {
            gPrefs.category = gRecord.category;
        }
        Key_SetCategory(gKeyRecordIndex, gRecord.category);
        KeyEditForm_UpdateCategory();
        KeyEditForm_UpdateTitle();
    }
}



Boolean KeyEditForm_HandleEvent(EventPtr event) {
    switch (event->eType) {
    case ctlSelectEvent:
        switch (event->data.ctlSelect.controlID) {
        case DoneBtn:
            KeyEditForm_Done();
            return true;
        case CategoryTrigger:
            KeyEditForm_CategorySelected();
            return true;
        default:
             return false;
        }

    case fldChangedEvent:
        if (event->data.fldChanged.fieldID == ID_NotesField) {
            KeyEditForm_UpdateScrollbar();
            return true;
        }
        break;

    case frmOpenEvent:
        KeyEditForm_FormOpen();
        return true;

    case frmCloseEvent:
         Edit_FormClose();
         return false;

    case keyDownEvent:
        return KeyEditForm_HandleKeyDownEvent(event);

    case menuEvent:
        if (!Common_HandleMenuEvent(event)
            && !KeyEditForm_HandleMenuEvent(event))
            App_NotImplemented();
        return true;

    case sclRepeatEvent:
    case sclExitEvent:
        KeyEditForm_Dragged(event);
        break;

    default:
    }

    return false;
}
