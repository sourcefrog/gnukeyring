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
#include "upgrade.h"
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




void App_ReportSysError(UInt16 msgID, Err err) {
    Char buf[256];

    *buf = '\0';
    SysErrString(err, buf, (UInt16) sizeof buf);
    FrmCustomAlert(msgID, buf, 0, 0);
}


static void App_LoadPrefs(void) {
    Int16 readBytes;
    Int16 size = sizeof(KeyringPrefsType);

    /* Set up the defaults first, then try to load over the top.  That
     * way, if the structure is too short or not there, we'll be left
     * with the defaults. */

    gPrefs.timeoutSecs = 60;
    gPrefs.category = dmAllCategories;
    
    PrefGetAppPreferences(kKeyringCreatorID,
			  kGeneralPref,
			  &gPrefs, &size,
			  (Boolean) true);
}


void App_SavePrefs(void) {
    PrefSetAppPreferences(kKeyringCreatorID,
			  kGeneralPref,
			  kAppVersion,
			  &gPrefs,
			  (UInt16) sizeof(KeyringPrefsType),
			  (Boolean) true);
}


static Boolean App_OfferUpgrade(void) {
    return FrmAlert(UpgradeAlert) == 0;	/* button 0 = convert */
}


static Boolean App_TooNew(void) {
    FrmAlert(TooNewAlert);
    return false;
}


static Err App_PrepareDB(void) {
    Err		err;
    UInt16	ver;
    
    /* If the database doesn't already exist, then we require the user
     * to set their password. */
    err = KeyDB_OpenExistingDB(&gKeyDB);
    if (err == dmErrCantFind) {
	if ((err = KeyDB_CreateDB())
	    || (err = KeyDB_OpenExistingDB(&gKeyDB))
	    || (err = KeyDB_CreateRingInfo())
	    || (err = KeyDB_CreateCategories()))
	    goto failDB;
	if (!SetPasswd_Run())
	    return 1;
    } else if (err) {
	goto failDB;
    } else {
	/* So, we opened a database OK.  Now, is it old, new, or just right? */
	if ((err = KeyDB_GetVersion(&ver)))
	    goto failDB;
	if (ver < kDatabaseVersion) {
	    if (App_OfferUpgrade()) {
		if ((err = UpgradeDB(ver)))
		    return err;
	    } else {
		return 1;
	    }
	} else if (ver > kDatabaseVersion) {
	    App_TooNew();
	    return 1;
	}
    }

    if ((err = KeyDB_MarkForBackup(gKeyDB)))
	goto failDB;

    return 0;


 failDB:
    App_ReportSysError(KeyDatabaseAlert, err);
    return err;
}


static Err App_Start(void) {
    Err err;

    Unlock_Reset();
    App_LoadPrefs();

    if ((err = App_PrepareDB()))
	return err;
	   
    FrmGotoForm(ListForm);
  
    return 0;
}


static void App_Stop(void) {
    App_SavePrefs();
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
	EvtGetEvent(&event, (Int32) evtWaitForever);
	
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
