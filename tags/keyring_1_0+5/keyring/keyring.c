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
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "keydb.h"
#include "passwd.h"
#include "uiutil.h"
#include "keyedit.h"
#include "crypto.h"

#include "prefs.h"
#include "snib.h"
#include "listform.h"
#include "error.h"
#include "beta.h"
#include "auto.h"
#include "uiutil.h"

/* TODO: Call MemSetDebugMode!!  Let people turn this on and off at
 * runtime through some kind of magic keystroke. */

// ======================================================================
// Globals

KeyringPrefsType gPrefs;


// ======================================================================
// Application methods



static void App_LoadPrefs(void) {
    Int16 size = sizeof(KeyringPrefsType);
    Int16 ret;

    /* Set up the defaults first, then try to load over the top.  That
     * way, if the structure is too short or not there, we'll be left
     * with the defaults. */

    gPrefs.timeoutSecs = 60;
    gPrefs.category = dmAllCategories;
    
    ret = PrefGetAppPreferences(kKeyringCreatorID,
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



static Err App_Start(void) {
    Err err;

    SysRandom(TimGetTicks() ^ SysRandom(0));
	
    App_LoadPrefs();
    Gkr_CheckBeta();

    if ((err = Snib_Init()))
	return err;

    if ((err = KeyDB_Init())) {
	Snib_Close();
        return err;
    }

    FrmGotoForm(ListForm);
    
    /* TODO: Make more sure that we don't leave the Snib open */

    return 0;
}


static void App_Stop(void) {
    /* TODO: Make more sure that we don't leave the Snib open */
    App_SavePrefs();
    FrmCloseAllForms();
    ErrNonFatalDisplayIf(!gKeyDB, __FUNCTION__ ": gKeyDB == null");
#ifdef ENABLE_OBLITERATE
    Unlock_ObliterateKey();
#endif
    Snib_Close();
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
#ifdef MEM_CHECK
	MemHeapCheck(0);
	MemHeapCheck(1);
#endif

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


Boolean Common_HandleMenuEvent(EventPtr event)
{
    FieldPtr		fld;
    Boolean		result = false;
    Int16		itemId;

    fld = UI_GetFocusObjectPtr();
    itemId = event->data.menu.itemID;
    
    switch (itemId) {
    case AboutCmd:
	App_AboutCmd();
	result = true;
	break;

    case ID_PrefsCmd:
	PrefsForm_Run();
	result = true;
	break;

    case SetPasswdCmd:
         if (App_CheckReadOnly())
              return true;
	if (UnlockForm_Run()) 
	    SetPasswd_Run();
	result = true;
	break;

    case KeyboardCmd:
         if (App_CheckReadOnly())
              return true;
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
         if (App_CheckReadOnly())
              return true;
         FldPaste(fld);
         result = true;
         break;

    case EditCut:
         if (App_CheckReadOnly())
              return true;
         FldCut(fld);
         result = true;
         break;
         
    case EditSelectAll:
	FldSetSelection(fld, 0, FldGetTextLength(fld));
	result = true;
	break;

    case EditUndo:
         if (App_CheckReadOnly())
              return true;
	FldUndo(fld);
	result = true;
	break;
    }

    return result;
}


/***********************************************************************
 *
 * FUNCTION:    RomVersionCompatible
 *
 * DESCRIPTION: This routine checks that a ROM version meets your
 *              minimum requirement.
 *
 * PARAMETERS:  requiredVersion - minimum rom version required
 *                                (see sysFtrNumROMVersion in SystemMgr.h 
 *                                for format)
 *              launchFlags     - flags that indicate if the application 
 *                                UI is initialized.
 *
 * RETURNED:    error code or zero if rom is compatible
 *                             
 *
 * REVISION HISTORY:
 *			Name	Date		Description
 *			----	----		-----------
 *			art	11/15/96	Initial Revision
 *
 ***********************************************************************/
static Err RomVersionCompatible (UInt32 requiredVersion, UInt16 launchFlags)
{
    UInt32 romVersion;

    // See if we have at least the minimum required version of the ROM or later.
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion < requiredVersion) {
        if ((launchFlags & (sysAppLaunchFlagNewGlobals | sysAppLaunchFlagUIApp)) ==
            (sysAppLaunchFlagNewGlobals | sysAppLaunchFlagUIApp)) {
            FrmAlert(NotEnoughFeaturesAlert);
            
            // Pilot 1.0 will continuously relaunch this app unless we switch to 
            // another safe one.
            if (romVersion < 0x02000000)
                AppLaunchWithCommand(sysFileCDefaultApp, sysAppLaunchCmdNormalLaunch, NULL);
        }
        
        return sysErrRomIncompatible;
    }
    
    return 0;
}


UInt32 PilotMain(UInt16 launchCode,
		 void UNUSED(*cmdPBP),
		 UInt16 UNUSED(launchFlags))
{
    Err err = 0;
    UInt32 rom30 = sysMakeROMVersion(3, 0, 0, sysROMStageRelease, 0);

    if ((err = RomVersionCompatible(rom30, launchFlags)))
        return err;

    if (launchCode == sysAppLaunchCmdNormalLaunch) {
	err = App_Start();
#ifdef MEM_CHECK
	MemHeapCheck(0);
	MemHeapCheck(1);
#endif
	if (!err) {
	    App_EventLoop();
	    App_Stop();
	}
    }

    /* TODO: We should handle: sysAppLaunchCmdSaveData,
     * sysAppLaunchCmdTimeChange, sysAppLaunchCmdFind,
     * sysAppLaunchCmdGoTo, sysAppLaunchCmdSystemLock, ... */

    return err;
}



Boolean App_CheckReadOnly(void)
{
     if (g_ReadOnly)
          FrmAlert(alertID_ReadOnly);
     return g_ReadOnly;
}

