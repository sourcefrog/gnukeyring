/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
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
#include "keydb.h"
#include "passwd.h"
#include "uiutil.h"
#include "keyedit.h"
#include "prefs.h"
#include "listform.h"

// ======================================================================
// Globals

// Reference to the keys database
DmOpenRef       gKeyDB;

UInt16		gKeyRecordIndex = kNoRecord;


KeyringPrefsType gPrefs;


/* If the keyring is unlocked, this holds the hash of the master
 * password, which is used for the two DES keys to decrypt records. */
UInt8		gRecordKey[kPasswdHashSize];


// ======================================================================
// Application methods




void App_ReportSysError(Char const * func, int err) {
    static Char buf[16];

    StrIToA(buf, err);
    FrmCustomAlert(SysErrAlert, func, buf, 0);
}


void App_LoadPrefs(void) {
    Int16 version;
    UInt16 size = sizeof(KeyringPrefsType);

    version = PrefGetAppPreferences(kKeyringCreatorID,
				    kGeneralPref,
				    &gPrefs, &size,
				    true);

    if (version == noPreferenceFound
	|| version != kKeyringVersion) {
	gPrefs.timeoutSecs = 60;
    }
}


void App_SavePrefs(void) {
    PrefSetAppPreferences(kKeyringCreatorID,
			  kGeneralPref,
			  kKeyringVersion,
			  &gPrefs,
			  sizeof(KeyringPrefsType),
			  true);
}


Err App_Start() {
    Err err;

    Unlock_Reset();
    App_LoadPrefs();

    /* If the database doesn't already exist, then we require the user
     * to set their password. */
    err = KeyDB_OpenExistingDB(&gKeyDB);
    if (err == dmErrCantFind) 
	err = KeyDB_CreateDB(&gKeyDB);
    if (err) {
	App_ReportSysError(__FUNCTION__, err);
	return err;
    }

    if (KeyDB_IsInitRequired()) {
	KeyDB_CreateAppInfo();
	if (!SetPasswd_Run())
	    return 1;
    }

    if ((err = KeyDB_MarkForBackup(gKeyDB)))
	return err;

    FrmGotoForm(ListForm);
  
    return 0;
}


void App_Stop(void) {
    FrmCloseAllForms();
    ErrNonFatalDisplayIf(!gKeyDB, __FUNCTION__ ": gKeyDB == null");
#ifdef ENABLE_OBLITERATE
    Unlock_ObliterateKey();
#endif
    DmCloseDatabase(gKeyDB);
}


static Boolean App_HandleEvent(EventPtr event)
{
    FormPtr	frm;
    UInt16		formId;
    Boolean	result = false;

    if (event->eType == frmLoadEvent) {
	// Load the form resource specified in the event then activate
	// the form.
	formId = event->data.frmLoad.formID;
	frm = FrmInitForm(formId);
	FrmSetActiveForm(frm);
	
	// Set the event handler for the form.  The handler of the
	// currently active form is called by FrmDispatchEvent each
	// time it receives an event.
	switch (formId) {
	case ListForm:
	    FrmSetEventHandler(frm, ListForm_HandleEvent);
	    result = true;
	    break;	

	case KeyEditForm:
	    FrmSetEventHandler(frm, KeyEditForm_HandleEvent);
	    result = true;
	    break;
	}
    }

    return result;
}


static void App_EventLoop(void)
{
    EventType	event;
    UInt16			error;
	
    do {
	EvtGetEvent(&event, evtWaitForever);
	
	if (!SysHandleEvent(&event))
	    if (!MenuHandleEvent(0, &event, &error))
		if (!App_HandleEvent(&event))
		    FrmDispatchEvent(&event);
    } while (event.eType != appStopEvent);
}


void App_AboutCmd(void) {
    FormPtr prevFrm = FrmGetActiveForm();
    FormPtr frm = FrmInitForm(AboutForm);

    FrmSetActiveForm(frm);
    FrmDoDialog(frm);
    if (prevFrm)
	FrmSetActiveForm(prevFrm);
    FrmDeleteForm(frm);
}


void App_NotImplemented(void) {
    FrmAlert(NotImplementedAlert);
}


Boolean Common_HandleMenuEvent(EventPtr event)
{
    FieldPtr fld;
    Boolean result = false;

    fld = UI_GetFocusObjectPtr();
    
    switch (event->data.menu.itemID) {
    case AboutCmd:
	App_AboutCmd();
	result = true;
	break;

    case PrefsCmd:
	PrefsForm_Run();
	result = true;
	break;

    case SetPasswdCmd:
	if (UnlockForm_Run()) 
	    SetPasswd_Run();
	result = true;
	break;

    case KeyboardCmd:
	SysKeyboardDialog(kbdDefault);
	result = true;
	break;

    case GraffitiReferenceCmd:
	SysGraffitiReferenceDialog(referenceDefault);
	result = true;
	break;

    case EditCopy:
	FldCopy(fld);
	result = true;
	break;

    case EditPaste:
	FldPaste(fld);
	result = true;
	break;

    case EditCut:
	FldCut(fld);
	result = true;
	break;

    case EditSelectAll:
	FldSetSelection(fld, 0, FldGetTextLength(fld));
	result = true;
	break;

    case EditUndo:
	FldUndo(fld);
	result = true;
	break;
    }

    return result;
}


UInt32 PilotMain(UInt16 launchCode,
		 void UNUSED(*cmdPBP),
		 UInt16 UNUSED(launchFlags))
{
    Err err = 0;

    if (launchCode == sysAppLaunchCmdNormalLaunch) {
	err = App_Start();
	if (!err) {
	    App_EventLoop();
	    App_Stop();
	}
    }

    return err;
}
