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

/*
 * TODO: Newline in single-line fields should move down one, perhaps?
 * Really this is only useful on POSE -- on the real system, people
 * can just use the next-field character.
 */


/* This keeps an unpacked version of the record currently being
 * edited.  They're periodically sync'd up; e.g. just before saving.
 *
 * It's a bit unfortunate to keep it in a global like this, but the
 * problem is that the date isn't stored by the GUI control, so we
 * need somewhere to keep it.  */
static UnpackedKeyType *gRecord;

static GUI_SECTION void KeyEdit_Save(void);
static GUI_SECTION void KeyEdit_UpdateScrollbar(void);
static GUI_SECTION Boolean KeyEdit_IsDirty(void);
static GUI_SECTION Boolean KeyEdit_IsEmpty(void);
static GUI_SECTION void KeyEdit_MarkClean(void);
static GUI_SECTION void KeyEdit_DeleteKey(Boolean saveBackup);
static GUI_SECTION void KeyEdit_GetFields(void);


#define k_KeyName   0
#define k_Acct      1
#define k_Passwd    2
#define k_Notes     3
#define k_NumFields 4

// If the form is active, all these are valid.
static ControlPtr f_DateTrg;
static ScrollBarPtr f_NotesScrollBar;
static FormPtr   f_KeyEditForm;
static Boolean   f_dirty;
static FieldPtr  f_AllFields[k_NumFields];
static CryptoKey *gRecordKey;
static Boolean   gKeyDirty;
static DateType  f_lastChanged;

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
 * TODO: Check if the following still applies:
 * - I haven't isolated the next as it is sometimes intermittent: a
 * bus error results after selecting a record from the list then
 * pressing Page Up key.  I think it's somewhere in
 * KeyEdit_SetTitle(). -- dmgarner */
static GUI_SECTION void KeyEdit_UpdateTitle(void)
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


/* Update the category popuptrigger to show the current record's
 * category name. */
static GUI_SECTION void KeyEdit_UpdateCategory(void)
{
    Category_UpdateName(f_KeyEditForm, gRecord->category);
}


/* Set the text in the "set date" popup trigger to match the date in
 * the record. */
static GUI_SECTION void KeyEdit_SetDateTrigger(void)
{
    static Char dateBuf[longDateStrLength];
    DateFormatType fmt;
    Int16 year, month, day;
    
    fmt = (DateFormatType) PrefGetPreference(prefLongDateFormat);

    year  = f_lastChanged.year + 1904;
    month = f_lastChanged.month;
    day   = f_lastChanged.day;

    /* DateToAscii doesn't cope well if the date is unreasonable, so we
     * filter it a bit. */
    if (month < 1 || month > 12
	|| day < 1 || day > 31) {
	month = day = 1;
    }

    DateToAscii(month, day, year, fmt, dateBuf);
    CtlSetLabel(f_DateTrg, dateBuf);
}

#define EVEN(x) (((x)+1)&~1)
#define ENDMARKER 0xffff
/*
 * Wipe out all the fields on this form.
 */
static GUI_SECTION void KeyEdit_Clear(void)
{
    gRecord = MemPtrNew(sizeof(UnpackedKeyType) + 4*sizeof(UInt16));
    gRecord->numFields = 0;
    gRecord->plainText = MemPtrNew(2);
    *(UInt16 *)(gRecord->plainText) = ENDMARKER;
 
    gRecord->category = gPrefs.category;
    if (gRecord->category == dmAllCategories)
	gRecord->category = dmUnfiledCategory;
}

static GUI_SECTION void KeyEdit_ToUnpacked(void)
{
    FieldHeaderType *field;
    int i, offset;
    int plainLen = EVEN(FldGetTextLength(f_AllFields[k_KeyName]))
	+ EVEN(FldGetTextLength(f_AllFields[k_Acct]))
	+ EVEN(FldGetTextLength(f_AllFields[k_Passwd]))
	+ EVEN(FldGetTextLength(f_AllFields[k_Notes]))
	+ 4 + 5 * sizeof(FieldHeaderType) + 2;
    UInt16 category = gRecord->category;

    MemSet(gRecord->plainText, MemPtrSize(gRecord->plainText), 0);
    MemPtrFree(gRecord->plainText);
    MemSet(gRecord, MemPtrSize(gRecord), 0);
    MemPtrFree(gRecord);
    gRecord = MemPtrNew(sizeof(UnpackedKeyType) + 4*sizeof(UInt16));
    gRecord->numFields = 0;
    gRecord->plainText = MemPtrNew(plainLen);
    gRecord->category  = category;

    offset = 0;
    for (i = 0; i < 5; i++) {
	gRecord->fieldOffset[gRecord->numFields++] = offset;
	field = gRecord->plainText + offset;
	field->fieldID = i;
	field->reserved = 0;
	offset += sizeof(FieldHeaderType);
	switch (i) {
	case 0:
	    field->len = FldGetTextLength(f_AllFields[k_KeyName]);
	    if (field->len) {
		MemMove((char *) (gRecord->plainText + offset), 
			FldGetTextPtr(f_AllFields[k_KeyName]), field->len);
		offset += EVEN(field->len);
	    }
	    break;

	case 1:
	    field->len = FldGetTextLength(f_AllFields[k_Acct]);
	    if (field->len == 0) {
		offset -= sizeof(FieldHeaderType);
		gRecord->numFields--;
	    } else {
		MemMove((char *) (gRecord->plainText + offset), 
			FldGetTextPtr(f_AllFields[k_Acct]), field->len);
		offset += EVEN(field->len);
	    }
	    break;

	case 2:
	    field->len = FldGetTextLength(f_AllFields[k_Passwd]);
	    if (field->len == 0) {
		offset -= sizeof(FieldHeaderType);
		gRecord->numFields--;
	    } else {
		MemMove((char *) (gRecord->plainText + offset), 
			FldGetTextPtr(f_AllFields[k_Passwd]), field->len);
		offset += EVEN(field->len);
	    }
	    break;

	case 3:
	    if (!f_lastChanged.year && !f_lastChanged.month
		&& !f_lastChanged.day) {
		offset -= sizeof(FieldHeaderType);
		gRecord->numFields--;
	    } else {
		field->len = sizeof(DateType);
		*(DateType*)(gRecord->plainText + offset) = f_lastChanged;
		offset += sizeof(DateType);
	    }
	    break;

	case 4:
	    field->fieldID = NotesFieldID;
	    field->len = FldGetTextLength(f_AllFields[k_Notes]);
	    if (field->len == 0) {
		offset -= sizeof(FieldHeaderType);
		gRecord->numFields--;
	    } else {
		MemMove((char *) (gRecord->plainText + offset), 
			FldGetTextPtr(f_AllFields[k_Notes]), field->len);
		offset += EVEN(field->len);
	    }
	    break;
	}
    }
    *(UInt16 *)(gRecord->plainText + offset) = ENDMARKER;
}


#ifdef NOTIFY_SLEEP_HANDLER
static GUI_SECTION Err KeyEdit_Sleep(SysNotifyParamType *np) {
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
static GUI_SECTION void KeyEdit_Load(void)
{
    FormPtr     busyForm;
    UInt16      attr;
    MemHandle   record;


    busyForm = FrmInitForm(BusyDecryptForm);
    FrmSetActiveForm(busyForm);
    FrmDrawForm(busyForm);

    record = DmGetRecord(gKeyDB, gKeyRecordIndex);
    ErrFatalDisplayIf(!record, "couldn't query record");

    if (Record_Unpack(record, &gRecord, gRecordKey))
	KeyEdit_Clear();

    DmRecordInfo(gKeyDB, gKeyRecordIndex, &attr, 0, 0);
    gRecord->category = (attr & dmRecAttrCategoryMask);
 
    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);
    FrmSetActiveForm(f_KeyEditForm);
}

/*
 * Load the data for the current key into gRecord and update the form
 * elements.  If this is a new key, go back to a blank form.
 */
static GUI_SECTION void KeyEdit_FillField(FieldPtr field, char *data, unsigned int len) {
    MemHandle handle = MemHandleNew(len+1);
    char *ptr = MemHandleLock(handle);
    MemMove(ptr, data, len);
    ptr[len] = 0;
    MemHandleUnlock(handle);

    FldSetTextHandle(field, handle);
}

/*
 * Load the data for the current key into gRecord and update the form
 * elements.  If this is a new key, go back to a blank form.
 */
static GUI_SECTION void KeyEdit_FillData(void) {
    FieldHeaderType *fldHeader;
    unsigned int fldIndex, fldLen;

    gKeyDirty = false;

    if (gKeyRecordIndex == kNoRecord)
	KeyEdit_Clear();
    else
	KeyEdit_Load();

    if (gPrefs.category != dmAllCategories)
	gPrefs.category = gRecord->category;

    DateSecondsToDate(TimGetSeconds(), &f_lastChanged);

    for (fldIndex = 0; fldIndex < gRecord->numFields; fldIndex++) {
	fldHeader = (FieldHeaderType *)
	    (gRecord->plainText + gRecord->fieldOffset[fldIndex]);
	fldLen = fldHeader->len;
	switch (fldHeader->fieldID) {
	case 0: /* key name */
	    KeyEdit_FillField(f_AllFields[k_KeyName], 
			      (char*) (fldHeader + 1), fldLen);
	    break;
	case 1: /* account */
	    KeyEdit_FillField(f_AllFields[k_Acct], 
			      (char*) (fldHeader + 1), fldLen);
	    break;
	case 2: /* password */
	    KeyEdit_FillField(f_AllFields[k_Passwd], 
			      (char*) (fldHeader + 1), fldLen);
	    break;
	case 255: /* notes */
	    KeyEdit_FillField(f_AllFields[k_Notes], 
			      (char*) (fldHeader + 1), fldLen);
	    break;
	case 3: /* lastChanged */
	    f_lastChanged = *(DateType*) (fldHeader + 1);
	    break;
	}
    }

    KeyEdit_MarkClean();

    KeyEdit_SetDateTrigger();
    KeyEdit_UpdateCategory();
    KeyEdit_UpdateTitle();
    KeyEdit_UpdateScrollbar();
    FrmDrawForm(f_KeyEditForm);
}


/*
 * Frees the GUI fields.  Also overwrites everything with zeros.
 */
static GUI_SECTION void KeyEdit_FreeFields(void) {
    int i;

    for (i = 0; i < k_NumFields; i++) {
	MemHandle textH = FldGetTextHandle(f_AllFields[i]);
	FldSetTextHandle(f_AllFields[i], NULL);
	if (textH) {
	    MemSet(MemHandleLock(textH), MemHandleSize(textH), 0);
	    MemHandleUnlock(textH);
	    MemHandleFree(textH);
	}
    }
}

/*
 * Frees gRecord and all associated data.  Also overwrites everything
 * with zeros.
 */
static GUI_SECTION void KeyEdit_FreeRecord(void) {
    MemSet(gRecord->plainText, MemPtrSize(gRecord->plainText), 0);
    MemPtrFree(gRecord->plainText);
    MemSet(gRecord, MemPtrSize(gRecord), 0);
    MemPtrFree(gRecord);
}

/*
 * Save the record if any fields are dirty, and also update gRecord
 * from the field values.  If the record has been left empty, then
 * delete it rather than saving an empty record.
 */
static GUI_SECTION void KeyEdit_Commit(void)
{
    if (KeyEdit_IsEmpty()) {

	KeyEdit_DeleteKey(false); /* no backup */
	KeyEdit_MarkClean();

    } else if (KeyEdit_IsDirty()) {
	if (gKeyRecordIndex == kNoRecord) {
	    /* TODO: If this fails, do something. */
	    KeyDB_CreateNew(&gKeyRecordIndex);
	}
	f_needsSort = true;
	gKeyDirty = true;
	KeyEdit_ToUnpacked();
	KeyEdit_Save();
	KeyEdit_MarkClean();
    }
}


/* Save values from the field into the database, after taking them
 * through an unpacked struct into encrypted form.  The fields must
 * already be in gRecord->
 *
 * Note that we're not *necessarily* leaving the form or even the
 * record at this point: pressing the Page buttons saves the record
 * too. */
static GUI_SECTION void KeyEdit_Save(void) 
{
    FormPtr busyForm;

    busyForm = FrmInitForm(BusyEncryptForm);
    FrmSetActiveForm(busyForm);
    FrmDrawForm(busyForm);

    Record_SaveRecord(gRecord, gKeyRecordIndex, gRecordKey);
    Key_SetCategory(gKeyRecordIndex, gRecord->category);

    FrmEraseForm(busyForm);
    FrmDeleteForm(busyForm);

    FrmSetActiveForm(f_KeyEditForm);
}

/*
 * Mark all fields as clean; called just after we save
 */
static GUI_SECTION void KeyEdit_MarkClean(void)
{
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          FldSetDirty(f_AllFields[i], false);
     }
     f_dirty = false;
}


/* Check if any fields are dirty, i.e. have been modified by the
 * user. */
static GUI_SECTION Boolean KeyEdit_IsDirty(void)
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
static GUI_SECTION Boolean KeyEdit_IsEmpty(void)
{
     Int16 i;

     for (i = 0; i < k_NumFields; i++) {
          if (FldGetTextLength(f_AllFields[i]))
               return false;
     }

     return true;
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
GUI_SECTION void KeyEdit_GotoRecord(UInt16 recordIdx)
{
    /* If we are active, commit the current record. */
    if (gEditFormActive) {
	KeyEdit_Commit();

	/* Check that database is still unlocked
	 */
	if (!Unlock_GetKey(false, NULL)) {
	    /* We leave the edit form */
	    FrmGotoForm(ListForm);
	    return;
	}

	KeyEdit_FreeRecord();
	KeyEdit_FreeFields();
	if (gKeyRecordIndex != kNoRecord)
	    DmReleaseRecord(gKeyDB, gKeyRecordIndex, gKeyDirty);
	gKeyRecordIndex = recordIdx;
	KeyEdit_FillData();
    } else {
	gRecordKey = MemPtrNew(sizeof(CryptoKey));
	if (!gRecordKey) {
	    ErrAlert(memErrNotEnoughSpace);
	    return;
	}

	/* Unlock or return immediately. 
	 */
	if (!Unlock_GetKey(false, gRecordKey)) {
	    /* We don't enter the edit form */
	    MemPtrFree(gRecordKey);
	    return;
	}
	gKeyRecordIndex = recordIdx;
        FrmGotoForm(KeyEditForm);
    }
}


static GUI_SECTION void KeyEdit_GetFields(void)
{
    f_KeyEditForm = FrmGetActiveForm();

    f_AllFields[k_KeyName] = UI_GetObjectByID(f_KeyEditForm, ID_KeyNameField);
    f_AllFields[k_Acct] = UI_GetObjectByID(f_KeyEditForm, AccountField);
    f_AllFields[k_Passwd] = UI_GetObjectByID(f_KeyEditForm, PasswordField);
    f_AllFields[k_Notes] = UI_GetObjectByID(f_KeyEditForm, ID_NotesField);

    f_DateTrg = UI_GetObjectByID(f_KeyEditForm, DateTrigger);
    
    f_NotesScrollBar = UI_GetObjectByID(f_KeyEditForm, NotesScrollbar);
}


/*
 * Set run-time-only attributes on fields.  This is called each time the
 * form is opened.
 */
static GUI_SECTION void KeyEdit_PrepareFields(void)
{
    FieldAttrType attr;
    UInt32 encoding;

    FldGetAttributes(f_AllFields[k_Notes], &attr);
    attr.hasScrollBar = true;
    FldSetAttributes(f_AllFields[k_Notes], &attr);

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

    /* If encoding is latin use our special password font. */
    if (gPrefs.useCustomFonts && encoding == charEncodingPalmLatin) {
	FldSetFont(f_AllFields[k_Acct], fntPassword);
	FldSetFont(f_AllFields[k_Passwd], fntPassword);
    }
}


static GUI_SECTION void KeyEdit_FormOpen(void)
{
#ifdef NOTIFY_SLEEP_HANDLER
    UInt32      version;
#endif

    gEditFormActive = true;
    
#ifdef NOTIFY_SLEEP_HANDLER
    /* NotifyRegister is not present in 3.0.  We need to check for
     * (sysFtrCreator, sysFtrNumNotifyMgrVersion) to see if we can
     * call this.  
     *
     * This code is currently disabled.  We listen for vchrAutoOff
     * and vchrPowerOff in the main event loop instead.
     */
    if (FtrGet(sysFtrCreator, sysFtrNumNotifyMgrVersion, &version) == 0
	&& version)
	 SysNotifyRegister(gKeyDBCardNo, gKeyDBID, sysNotifySleepRequestEvent,
			   KeyEdit_Sleep, sysNotifyNormalPriority, NULL);
#endif

    f_needsSort = false;
    KeyEdit_GetFields();
    KeyEdit_PrepareFields();
    KeyEdit_FillData();
    FrmSetFocus(f_KeyEditForm,
                FrmGetObjectIndex(f_KeyEditForm, ID_KeyNameField));
}

static GUI_SECTION void KeyEdit_FormClose(void)
{
#ifdef NOTIFY_SLEEP_HANDLER
     UInt32 version;
#endif
     UInt32 uniqueId = 0;

     KeyEdit_Commit();
     if (gRecordKey) {
	 CryptoDeleteKey(gRecordKey);
	 MemPtrFree(gRecordKey);
	 gRecordKey = NULL;
     }

     KeyEdit_FreeRecord();
     KeyEdit_FreeFields();
     if (gKeyRecordIndex != kNoRecord) {
	 DmReleaseRecord(gKeyDB, gKeyRecordIndex, gKeyDirty);
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

#ifdef NOTIFY_SLEEP_HANDLER
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
static GUI_SECTION void KeyEdit_DeleteKey(Boolean saveBackup)
{
    /* Is there a record to remove ? */
    if (gKeyRecordIndex == kNoRecord)
	return;

    /* If we want to save a backup copy, commit the changes */
    if (saveBackup)
	KeyEdit_Commit();
    
    DmReleaseRecord(gKeyDB, gKeyRecordIndex, gKeyDirty);

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
static GUI_SECTION void KeyEdit_MaybeDelete(void)
{
     UInt16 buttonHit;
     FormPtr alert;
     Boolean saveBackup = false;

     if (App_CheckReadOnly())
          return;

     if (!KeyEdit_IsEmpty()) {
	 alert = FrmInitForm(ConfirmDeleteForm);
	 buttonHit = FrmDoDialog(alert);
	 saveBackup = CtlGetValue(UI_GetObjectByID(alert, SaveArchiveCheck));
	 FrmDeleteForm(alert);

	 if (buttonHit == CancelBtn)
	     return;
     }

     KeyEdit_DeleteKey(saveBackup);

     FrmGotoForm(ListForm);
}



static GUI_SECTION void KeyEdit_Generate(void)
{
    FormPtr     frm;
    MemHandle   h, oldH;

    if (App_CheckReadOnly())
         return;

    h = Generate_Run();
    if (!h)
        return;

    frm = f_KeyEditForm;
    oldH = FldGetTextHandle(f_AllFields[k_Passwd]);
    FldSetTextHandle(f_AllFields[k_Passwd], (MemHandle) h);
    if (oldH) {
	MemSet(MemHandleLock(oldH), MemHandleSize(oldH), 0);
	MemHandleUnlock(oldH);
	MemHandleFree(oldH);
    }
    FldSetDirty(f_AllFields[k_Passwd], true);
    FldDrawField(f_AllFields[k_Passwd]);

    DateSecondsToDate(TimGetSeconds(), &f_lastChanged);
    f_dirty = true;
    KeyEdit_SetDateTrigger();
}


/*
 * Export if possible.
 */
static GUI_SECTION void KeyEdit_MaybeExport(void)
{
     if (KeyEdit_IsEmpty()) {
          FrmAlert(alertID_ExportEmpty);
          return;
     }
     
     /* Save the record.  As a side effect, write into gRecord. */
     KeyEdit_Commit();
     ExportKey(gRecord);
}


static GUI_SECTION Boolean KeyEdit_HandleMenuEvent(EventPtr event)
{
    switch (event->data.menu.itemID) {
    case HelpCmd:
        FrmHelp(KeyEditHelp);
        return true;
        
    case DeleteKeyCmd:
	KeyEdit_MaybeDelete();
	return true;

    case GenerateCmd:
        KeyEdit_Generate();
        return true;

    case ExportMemoCmd:
	KeyEdit_MaybeExport();
        return true;

    case ID_UndoAllCmd:
	if (!App_CheckReadOnly()) {
	
	    /*
	     * Throw away all the changes to the current key.  If this is
	     * an existing key, reload it from the database.  If this is a
	     * new key, go back to a blank form.  
	     */
	    if (gKeyRecordIndex != kNoRecord)
		DmReleaseRecord(gKeyDB, gKeyRecordIndex, gKeyDirty);
	    KeyEdit_FreeRecord();
	    KeyEdit_FreeFields();
	    KeyEdit_FillData();
	}
	return true;
        
    default:
        return false;
    }
}


static GUI_SECTION void KeyEdit_UpdateScrollbar(void)
{
    UInt16 textHeight, fieldHeight, maxValue, scrollPos;

    FldGetScrollValues(f_AllFields[k_Notes], &scrollPos, &textHeight, &fieldHeight);

    if (textHeight > fieldHeight)
        maxValue = textHeight - fieldHeight;
    else if (scrollPos)
        maxValue = scrollPos;
    else
        maxValue = 0;

    SclSetScrollBar(f_NotesScrollBar, scrollPos, 0, maxValue, fieldHeight-1);
}


static GUI_SECTION void KeyEdit_Dragged(EventPtr event)
{
    Int32 lines = event->data.sclExit.newValue - event->data.sclExit.value;
    WinDirectionType direction;

    if (lines < 0) {
        lines = -lines;
        direction = winUp;
    } else {
        direction = winDown;
    }
    
    FldScrollField(f_AllFields[k_Notes], lines, direction);
}


/*
 * If possible, scroll the notes field.  Otherwise, flip forward or
 * backward by one record.  Before flipping records, commit changes
 * and act appropriately if the record was actually discarded.
 */
static GUI_SECTION void KeyEdit_PageButton(WinDirectionType dir)
{
    if (FldScrollable(f_AllFields[k_Notes], dir)) {
	Int16 lines;

        lines = FldGetVisibleLines(f_AllFields[k_Notes]);
        FldScrollField(f_AllFields[k_Notes], lines, dir);
        KeyEdit_UpdateScrollbar();
    } else {
	UInt16 recIndex = gKeyRecordIndex;
	Int16 direction;
	
	direction = (dir == winDown) ? dmSeekForward : dmSeekBackward;
	if (DmSeekRecordInCategory(gKeyDB, &recIndex, 
				   1, direction, gPrefs.category) == errNone)
	    KeyEdit_GotoRecord(recIndex);
    }
}



static GUI_SECTION Boolean KeyEdit_Arrow(int dir)
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


static GUI_SECTION Boolean KeyEdit_HandleKeyDownEvent(EventPtr event)
{
    const int chr = event->data.keyDown.chr;
    
    if (TxtCharIsHardKey(event->data.keyDown.modifiers, chr)) {
	FrmGotoForm(ListForm);
	return true;
    }
    switch (chr) {
    case pageUpChr:
    case pageDownChr:
        KeyEdit_PageButton(chr == pageDownChr ? winDown : winUp);
        return true;

    case nextFieldChr:
    case prevFieldChr:
        return KeyEdit_Arrow(chr == nextFieldChr ? +1 : -1);

    default:
        return false;
    }
}


static GUI_SECTION void KeyEdit_ChooseDate(void) {
    Boolean ok;
    MemHandle handle;
    Char *title;
    Int16 year, month, day;

    year  = f_lastChanged.year + 1904;
    month = f_lastChanged.month;
    day   = f_lastChanged.day;

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

	f_lastChanged.year = year - 1904;
	f_lastChanged.month = month;
	f_lastChanged.day = day;
	f_dirty = true;
	
	KeyEdit_SetDateTrigger();
    }
}


static GUI_SECTION void KeyEdit_CategorySelected(void)
{
    Boolean categoryChanged;
    
    if (App_CheckReadOnly())
	return;
    
    categoryChanged = Category_Selected(&gRecord->category, false);
    if (categoryChanged) {
	f_dirty = true;
	KeyEdit_UpdateCategory();
	if (gPrefs.category != dmAllCategories) {
	    gPrefs.category = gRecord->category;
	    KeyEdit_UpdateTitle();
	}
    }
}



GUI_SECTION Boolean KeyEdit_HandleEvent(EventPtr event)
{
    switch (event->eType) {
    case ctlSelectEvent:
        switch (event->data.ctlSelect.controlID) {
        case LockBtn:
            Snib_Eradicate ();
	    FrmGotoForm(ListForm);
            return true;
        case DoneBtn:
	    FrmGotoForm(ListForm);
            return true;
	case GenerateBtn:
	    KeyEdit_Generate();
	    return true;
	case DateTrigger:
	    KeyEdit_ChooseDate();
	    return true;
        case CategoryTrigger:
            KeyEdit_CategorySelected();
            return true;
        default:
	    return false;
        }

    case fldChangedEvent:
        if (event->data.fldChanged.fieldID == ID_NotesField) {
            KeyEdit_UpdateScrollbar();
            return true;
        }
        break;

    case frmOpenEvent:
        KeyEdit_FormOpen();
        return true;

    case frmSaveEvent:
	KeyEdit_Commit();
	return true;

    case frmCloseEvent:
	KeyEdit_FormClose();
	return false;

    case keyDownEvent:
        return KeyEdit_HandleKeyDownEvent(event);

    case menuEvent:
        if (Common_HandleMenuEvent(event)
            || KeyEdit_HandleMenuEvent(event))
	    return true;
	break;

    case sclRepeatEvent:
    case sclExitEvent:
        KeyEdit_Dragged(event);
        break;

    default:
    }

    return false;
}
