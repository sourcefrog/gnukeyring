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

// If the form is active, all these are valid.
static FieldPtr f_NotesFld, f_KeyNameFld, f_AcctFld, f_PasswdFld;
static ControlPtr f_DateTrg;
static ScrollBarPtr f_NotesScrollBar;
static FormPtr f_KeyEditForm;
static Boolean f_dirty;

#define k_NumFields 4
static FieldPtr f_AllFields[k_NumFields];
static CryptoKey gRecordKey;

/* Index of the current record in the database as a whole. */
static UInt16 gKeyRecordIndex = kNoRecord;

/* True if we should sort the database on leaving this form.  At the
 * moment we set this on any modification, although we could perhaps
 * be a bit more selective. */
static Boolean f_needsSort;

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
    MemHandle titleHandle;
    Char * titleTemplate;
    UInt16 pos, total;
    Char posStr[maxStrIToALen];
    Char totalStr[maxStrIToALen];
    Char * keyFormTitle;
    
    total = DmNumRecordsInCategory(gKeyDB, gPrefs.category);
    /* 1-based count */
    if (gKeyRecordIndex == kNoRecord) 
	pos = ++total;
    else 
	pos = 1 + DmPositionInCategory(gKeyDB, gKeyRecordIndex, 
				       gPrefs.category);
    
    titleHandle = DmGetResource(strRsc, TitleTemplateStr);
    titleTemplate = MemHandleLock(titleHandle);
    ErrFatalDisplayIf(!titleTemplate, __FUNCTION__ ": no titleTemplate");

    StrIToA(posStr, pos);
    StrIToA(totalStr, total);

    keyFormTitle = UI_TxtParamString(titleTemplate, posStr, totalStr, NULL, NULL); 
    FrmCopyTitle(f_KeyEditForm, keyFormTitle);
    MemPtrFree(keyFormTitle);
    MemPtrUnlock(titleTemplate);
    DmReleaseResource(titleHandle);

    return;
}


/* Set the text in the "set date" popup trigger to match the date in
 * the record. */
static void KeyEditForm_SetDateTrigger(void)
{
    static Char dateBuf[dateStringLength];
    DateFormatType fmt;
    Int16 year, month, day;
    
    fmt = (DateFormatType) PrefGetPreference(prefLongDateFormat);

    year  = gRecord.lastChange.year + 1904;
    month = gRecord.lastChange.month;
    day   = gRecord.lastChange.day;

    /* DateToAscii doesn't cope well if the date is unreasonable, so we
     * filter it a bit. */
    if (month < 1 || month > 12
	|| day < 1 || day > 31) {
	month = day = 1;
    }

    DateToAscii(month, day, year, fmt, dateBuf);
    CtlSetLabel(f_DateTrg, dateBuf);
}



static void KeyEditForm_FromUnpacked(void)
{
    FldFreeMemory(f_KeyNameFld);
    FldSetTextHandle(f_KeyNameFld, (MemHandle) gRecord.nameHandle);
    FldFreeMemory(f_AcctFld);
    FldSetTextHandle(f_AcctFld, (MemHandle) gRecord.acctHandle);
    FldFreeMemory(f_PasswdFld);
    FldSetTextHandle(f_PasswdFld, (MemHandle) gRecord.passwdHandle);
    FldFreeMemory(f_NotesFld);
    FldSetTextHandle(f_NotesFld, (MemHandle) gRecord.notesHandle);
    KeyEditForm_SetDateTrigger();
}


/*
 * Wipe out all the fields on this form.
 */
static void KeyEditForm_Clear(void)
{
    Int16 i;
    
    for (i = 0; i < k_NumFields; i++)
	FldDelete(f_AllFields[i], 0, (UInt16) -1);
    
    DateSecondsToDate(TimGetSeconds(), &gRecord.lastChange);
    KeyEditForm_SetDateTrigger();
}


static void KeyEditForm_ToUnpacked(UnpackedKeyType *u)
{
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


static void KeyEditForm_Done(void)
{
    FrmGotoForm(ListForm);
}

#if 0
static Err KeyEditForm_Sleep(SysNotifyParamType *np) {
    Err err;
    UInt16 cardNo;
    LocalID dbID;
    DmSearchStateType dss;

    /* Defer sleeping */
    ((SleepEventParamType *) (np->notifyDetailsP))->deferSleep++;

    /* First enqueue events to restart application */
    err = DmGetNextDatabaseByTypeCreator(true, &dss,
                                         sysFileTApplication,
                                         kKeyringCreatorID,
                                         true, &cardNo, &dbID);
    ErrNonFatalDisplayIf(err != errNone,"Failed to launch application!");
    SysUIAppSwitch(cardNo, dbID, kKeyringResumeSleepLaunch, NULL);

    return 0;
}
#endif

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
    record = DmGetRecord(gKeyDB, gKeyRecordIndex);
    ErrNonFatalDisplayIf(!record, "couldn't query record");
    recPtr = MemHandleLock(record);
    ErrNonFatalDisplayIf(!recPtr, "couldn't lock record");
    
    busyForm = FrmInitForm(BusyDecryptForm);
    FrmSetActiveForm(busyForm);
    FrmDrawForm(busyForm);

    Keys_UnpackRecord(recPtr, &gRecord, gRecordKey);
    MemHandleUnlock(record);
    KeyRecord_GetCategory(gKeyRecordIndex, &gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);
    FrmSetActiveForm(f_KeyEditForm);

    KeyEditForm_FromUnpacked();
}


static void Key_SetNewRecordCategory(void)
{
    if (gPrefs.category == dmAllCategories)
	gRecord.category = dmUnfiledCategory;
    else
	gRecord.category = gPrefs.category;
}


/*
 * Save the record if any fields are dirty, and also update gRecord
 * from the field values.  If the record has been left empty, then
 * delete it rather than saving an empty record.
 */
static void KeyEditForm_Commit(void)
{
    if (KeyEditForm_IsEmpty()) {

	Edit_DeleteKey(false); /* no backup */
	KeyEditForm_MarkClean();

    } else if (KeyEditForm_IsDirty()) {
	if (gKeyRecordIndex == kNoRecord) {
	    /* TODO: If this fails, do something. */
	    KeyDB_CreateNew(&gKeyRecordIndex);
	    Key_SetNewRecordCategory();
	}
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
    FrmSetActiveForm(busyForm);
    FrmDrawForm(busyForm);

    Keys_SaveRecord(&gRecord, gKeyRecordIndex, gRecordKey);
    Key_SetCategory(gKeyRecordIndex, gRecord.category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);

    FrmSetActiveForm(f_KeyEditForm);
}


/* Update the category popuptrigger to show the current record's
 * category name. */
static void KeyEditForm_UpdateCategory(void)
{
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
static void Edit_MaybeUndoAll(void)
{
     if (App_CheckReadOnly())
          return;

     if (gKeyRecordIndex == kNoRecord) {
	 KeyEditForm_Clear();
     } else {
	 /* TODO: Check that this works OK if the record is
	  * newly-allocated and zero length. */
	 DmReleaseRecord(gKeyDB, gKeyRecordIndex, false);
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
     f_dirty = false;
}


/* Check if any fields are dirty, i.e. have been modified by the
 * user. */
static Boolean KeyEditForm_IsDirty(void)
{
     Int16 i;

     if (f_dirty)
	 return true;

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
          if (FldGetTextLength(f_AllFields[i]))
               return false;
     }

     return true;
}


static void KeyEditForm_OpenRecord(void)
{
    if (gKeyRecordIndex != kNoRecord) 
        KeyEditForm_Load();
    else
	KeyEditForm_Clear();

    if (gPrefs.category != dmAllCategories)
	gPrefs.category = gRecord.category;

    KeyEditForm_UpdateAll();
    FrmSetFocus(f_KeyEditForm,
                FrmGetObjectIndex(f_KeyEditForm, ID_KeyNameField));
}


/*
 * Go to the record with the specified index.  It has to work
 * regardless of the currently active form.  If key edit form is
 * already active it commits the last record before attempting to
 * switch the record.
 * 
 * If the timeout has passed then we do not allow a new record to be
 * opened.  The user must either re-enter their password, or he gets
 * transferred to the key list.
 */
void KeyEditForm_GotoRecord(UInt16 recordIdx)
{
    /* If we are active, commit the current record. */
    if (gEditFormActive)
	KeyEditForm_Commit();

    /* Unlock or return immediately. 
     */
    if (!Unlock_GetKey(false, gRecordKey)) {
	/* We leave the edit form */
	FrmGotoForm(ListForm);
	return;
    }

    if (gKeyRecordIndex != kNoRecord)
	DmReleaseRecord(gKeyDB, gKeyRecordIndex, false);
    
    gKeyRecordIndex = recordIdx;

    if (gEditFormActive)
	KeyEditForm_OpenRecord();
    else
        FrmGotoForm(KeyEditForm);
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
    
    f_DateTrg = UI_GetObjectByID(f_KeyEditForm, DateTrigger);
    
    f_NotesScrollBar = UI_GetObjectByID(f_KeyEditForm, NotesScrollbar);
}


/*
 * Set run-time-only attributes on fields.  This is called each time the
 * form is opened.
 */
static void Edit_PrepareFields(void)
{
    FieldAttrType attr;
    UInt32 encoding;

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

    if (FtrGet(sysFtrCreator, sysFtrNumEncoding, &encoding))
	/* if feature not found it is palm latin */
	encoding = charEncodingPalmLatin;

    /* If encoding is not latin, use default fonts. */
    if (encoding == charEncodingPalmLatin) {
	FldSetFont(f_AllFields[2], fntPassword);
	FldSetFont(f_AllFields[3], fntPassword);
    }
}


static void KeyEditForm_FormOpen(void)
{
#if 0
    UInt32      version;
#endif

    gEditFormActive = true;
    
#if 0
    /* NotifyRegister is not present in 3.0.  We need to check for
     * (sysFtrCreator, sysFtrNumNotifyMgrVersion) to see if we can
     * call this.  It might be better to set an alarm to lock after
     * the specified time instead.  Maybe we could reuse the snib
     * alarm.
     */
    if (FtrGet(sysFtrCreator, sysFtrNumNotifyMgrVersion, &version) == 0
	&& version)
	 SysNotifyRegister(gKeyDBCardNo, gKeyDBID, sysNotifySleepRequestEvent,
			   KeyEditForm_Sleep, sysNotifyNormalPriority, NULL);
#endif

    f_needsSort = false;
    KeyEditForm_GetFields();
    Edit_PrepareFields();
    KeyEditForm_OpenRecord();
}

static void Edit_FormClose(void)
{
#if 0
     UInt32 version;
#endif
     UInt32 uniqueId = 0;

     KeyEditForm_Commit();
     MemSet(gRecordKey, sizeof(gRecordKey), 0);

     if (gKeyRecordIndex != kNoRecord) {
	 DmReleaseRecord(gKeyDB, gKeyRecordIndex, false);
	 /* Save the uniqueId, so we find the record again after
          * sorting. */
	 DmRecordInfo(gKeyDB, gKeyRecordIndex, NULL, &uniqueId, NULL);
	 gKeyRecordIndex = kNoRecord;
     }

     if (f_needsSort)
	 Keys_Sort();

     /* This is not necessarily a reasonable index, but the list form
      * will check it before use. */
     if (!uniqueId)
	 f_FirstIdx = 0;
     else {
	 UInt16 index;
	 DmFindRecordByID(gKeyDB, uniqueId, &index);
	 f_FirstIdx = DmPositionInCategory(gKeyDB, index, gPrefs.category);
     }

#if 0
     if (FtrGet(sysFtrCreator, sysFtrNumNotifyMgrVersion, &version) == 0
	 && version) {
	  SysNotifyUnregister(gKeyDBCardNo,
			      gKeyDBID,
			      sysNotifySleepRequestEvent,
			      sysNotifyNormalPriority);
     }
#endif
     gEditFormActive = false;
}


/*
 * Delete the current record.
 */
static void Edit_DeleteKey(Boolean saveBackup)
{
    /* Is there a record to remove ? */
    if (gKeyRecordIndex == kNoRecord)
	return;

    DmReleaseRecord(gKeyDB, gKeyRecordIndex, false);

    /* I don't think there's any need to sort here, because nothing else
     * has moved. */

    if (saveBackup) {
        DmArchiveRecord(gKeyDB, gKeyRecordIndex);
    } else {
        DmDeleteRecord(gKeyDB, gKeyRecordIndex);
    }

    // Move to the end to make the ordering of the remaining
    // records simple.
    DmMoveRecord(gKeyDB, gKeyRecordIndex, DmNumRecords(gKeyDB));
    gKeyRecordIndex = kNoRecord;
}


/*
 * Delete the record if the user is sure that's what they want.
 * Return true if deleted and we should return to the list form,
 * otherwise false.
 *
 * TODO: Check if the record is empty; if it is delete without seeking
 * confirmation.
 */
static void Edit_MaybeDelete(void)
{
     UInt16 buttonHit;
     FormPtr alert;
     Boolean saveBackup = false;

     if (App_CheckReadOnly())
          return;

     if (!KeyEditForm_IsEmpty()) {
	 alert = FrmInitForm(ConfirmDeleteForm);
	 buttonHit = FrmDoDialog(alert);
	 saveBackup = CtlGetValue(UI_GetObjectByID(alert, SaveArchiveCheck));
	 FrmDeleteForm(alert);

	 if (buttonHit == CancelBtn)
	     return;
     }

     /* If we want to save a backup copy, commit the changes */
     if (saveBackup)
	 KeyEditForm_Commit();

     Edit_DeleteKey(saveBackup);

     FrmGotoForm(ListForm);
}



static void KeyEditForm_Generate(void)
{
    FormPtr     frm;
    MemHandle   h;
    FieldPtr    passwdFld;

    if (App_CheckReadOnly())
         return;

    h = Generate_Run();
    if (!h)
        return;

    frm = f_KeyEditForm;
    passwdFld = UI_GetObjectByID(frm, PasswordField);
    FldFreeMemory(passwdFld);
    FldSetTextHandle(passwdFld, (MemHandle) h);
    FldSetDirty(passwdFld, true);
    FldDrawField(passwdFld);

    DateSecondsToDate(TimGetSeconds(), &gRecord.lastChange);
    f_dirty = true;
    KeyEditForm_SetDateTrigger();
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


static Boolean KeyEditForm_HandleMenuEvent(EventPtr event)
{
    switch (event->data.menu.itemID) {
    case HelpCmd:
        FrmHelp(KeyEditHelp);
        return true;
        
    case DeleteKeyCmd:
	Edit_MaybeDelete();
	return true;

    case GenerateCmd:
        KeyEditForm_Generate();
        return true;

    case ExportMemoCmd:
	Edit_MaybeExport();
        return true;

    case ID_UndoAllCmd:
	Edit_MaybeUndoAll();
	return true;
        
    default:
        return false;
    }
}


static void KeyEditForm_UpdateScrollbar(void)
{
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


static void KeyEditForm_Dragged(EventPtr event)
{
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
 * If possible, scroll the notes field.  Otherwise, flip forward or
 * backward by one record.  Before flipping records, commit changes
 * and act appropriately if the record was actually discarded.
 */
static void KeyEditForm_PageButton(WinDirectionType dir)
{
    if (FldScrollable(f_NotesFld, dir)) {
	Int16 lines;

        lines = FldGetVisibleLines(f_NotesFld);
        FldScrollField(f_NotesFld, lines, dir);
        KeyEditForm_UpdateScrollbar();
    } else {
	UInt16 recIndex = gKeyRecordIndex;
	Int16 direction;
	
	direction = (dir == winDown) ? dmSeekForward : dmSeekBackward;
	if (DmSeekRecordInCategory(gKeyDB, &recIndex, 
				   1, direction, gPrefs.category) == errNone)
	    KeyEditForm_GotoRecord(recIndex);
    }
}



static Boolean KeyEditForm_Arrow(int dir)
{
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


static Boolean KeyEditForm_HandleKeyDownEvent(EventPtr event)
{
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


static void KeyEditForm_ChooseDate(void) {
    Boolean ok;
    MemHandle handle;
    Char *title;
    Int16 year, month, day;

    year  = gRecord.lastChange.year + 1904;
    month = gRecord.lastChange.month;
    day   = gRecord.lastChange.day;

    /* Limit to protect against SelectDay aborting. */
    if (month < 1 || month > 12
	|| day < 1 || day > 31) {
	month = day = 1;
    }

    title = MemHandleLock(handle = DmGetResource (strRsc, ChangeDateStr));
    ok = SelectDay(selectDayByDay, &month, &day, &year, title);
    MemHandleUnlock(handle);
    DmReleaseResource(handle);

    if (ok) {

	gRecord.lastChange.year = year - 1904;
	gRecord.lastChange.month = month;
	gRecord.lastChange.day = day;
	f_dirty = true;
	
	KeyEditForm_SetDateTrigger();
    }
}


static void KeyEditForm_CategorySelected(void)
{
    Boolean categoryChanged;
    
    if (App_CheckReadOnly())
	return;
    
    categoryChanged = Category_Selected(&gRecord.category, false);
    if (categoryChanged) {
	f_dirty = true;
	if (gPrefs.category != dmAllCategories) {
	    gPrefs.category = gRecord.category;
	}
	KeyEditForm_UpdateCategory();
	KeyEditForm_UpdateTitle();
    }
}



Boolean KeyEditForm_HandleEvent(EventPtr event)
{
    switch (event->eType) {
    case ctlSelectEvent:
        switch (event->data.ctlSelect.controlID) {
        case LockBtn:
            Snib_Eradicate ();
            KeyEditForm_Done();
            return true;
        case DoneBtn:
            KeyEditForm_Done();
            return true;
	case GenerateBtn:
	    KeyEditForm_Generate();
	    return true;
	case DateTrigger:
	    KeyEditForm_ChooseDate();
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

    case frmSaveEvent:
	KeyEditForm_Commit();
	return true;

    case frmCloseEvent:
	Edit_FormClose();
	return false;

    case keyDownEvent:
        return KeyEditForm_HandleKeyDownEvent(event);

    case menuEvent:
        if (Common_HandleMenuEvent(event)
            || KeyEditForm_HandleMenuEvent(event))
	    return true;
	break;

    case sclRepeatEvent:
    case sclExitEvent:
        KeyEditForm_Dragged(event);
        break;

    default:
    }

    return false;
}
