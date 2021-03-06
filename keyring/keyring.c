/* -*- c-basic-offset: 4; c-file-style: java; -*-
 *
 * $Id$
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

// ======================================================================
// Globals

KeyringPrefsType gPrefs;
Boolean gEditFormActive;

static Boolean gSleeping;
static MemHandle handleFontStar;
static MemHandle handleFontPW;


// ======================================================================
// Application methods

static void App_LoadPrefs(void) {
    Int16 size = sizeof(KeyringPrefsType);
    Int16 version;

    /* Set up the defaults first, then try to load over the top.  That
     * way, if the structure is too short or not there, we'll be left
     * with the defaults. */

    gPrefs.timeoutSecs = 60;
    gPrefs.category = dmAllCategories;
    gPrefs.useCustomFonts = false;
    
    version = PrefGetAppPreferences(kKeyringCreatorID,
				    kGeneralPref,
				    &gPrefs, &size,
				    (Boolean) true);

#ifdef BETA
    /* If this is a beta version and the previous version was different
     * open the beta alert dialog.
     */
    if (version != kAppVersion)
	FrmAlert(BetaAlert);
#endif
}


static void App_SavePrefs(void)
{
    PrefSetAppPreferences(kKeyringCreatorID,
			  kGeneralPref,
			  kAppVersion,
			  &gPrefs,
			  (UInt16) sizeof(KeyringPrefsType),
			  (Boolean) true);
}

void App_LoadFonts(void)
{
    UInt32 winVersion = 0;
    UInt32 resID = 'NFNT';
    
    if (handleFontStar == NULL) {
	if (FtrGet(sysFtrCreator, sysFtrNumWinVersion, &winVersion) == 0
	    && winVersion >= 4)
	    resID = 'nfnt';

	handleFontStar = DmGetResource(resID, StarFont);
	FntDefineFont(fntStar, (FontPtr)MemHandleLock(handleFontStar));
	handleFontPW = DmGetResource(resID, PasswordFont);
	FntDefineFont(fntPassword, (FontPtr)MemHandleLock(handleFontPW));
    }
}

void App_ReleaseFonts(void)
{
    if (handleFontStar != NULL) {
	MemHandleUnlock(handleFontStar);
	DmReleaseResource(handleFontStar);
	MemHandleUnlock(handleFontPW);
	DmReleaseResource(handleFontPW);
    }
}

static Err App_Start(void)
{
    Err err;

    App_LoadPrefs();

    if (gPrefs.useCustomFonts)
	App_LoadFonts();

    if ((err = Snib_Init()))
	return err;

    if ((err = KeyDB_Init()))
	return err;

    Secrand_Init();
    
    /* TODO: Make more sure that we don't leave the Snib open */

    return 0;
}


static void App_Stop(void)
{
    App_SavePrefs();
    Secrand_Close();
    FrmSaveAllForms ();
    FrmCloseAllForms();
    ErrNonFatalDisplayIf(!gKeyDB, __FUNCTION__ ": gKeyDB == null");
    DmCloseDatabase(gKeyDB);
    App_ReleaseFonts();
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
	    FrmSetEventHandler(frm, KeyEdit_HandleEvent);
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
	Secrand_AddEventRandomness(&event);

	if (event.eType == keyDownEvent
	    && (event.data.keyDown.chr == vchrAutoOff
		|| event.data.keyDown.chr == vchrPowerOff
		|| event.data.keyDown.chr == vchrLock)) {
	    gSleeping = true;
	    if (gEditFormActive && 
		(event.data.keyDown.chr == vchrLock
		 || !Snib_RetrieveKey(NULL))) {
		FrmSaveAllForms();
		FrmCloseAllForms();
		FrmGotoForm(ListForm);
	    }
	} else if (event.eType != nilEvent
		   && (event.eType != keyDownEvent 
		       || event.data.keyDown.chr != vchrLateWakeup)) {
	    Snib_Event();
	    gSleeping = false;
	}
	
	if (!SysHandleEvent(&event))
	    if (!MenuHandleEvent(0, &event, &error))
		if (!App_HandleEvent(&event))
		    FrmDispatchEvent(&event);
    } while (event.eType != appStopEvent);
}


static void App_AboutCmd(void)
{
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
    Int16		itemId;

    fld = UI_GetFocusObjectPtr();
    itemId = event->data.menu.itemID;
    
    switch (itemId) {
    case AboutCmd:
	App_AboutCmd();
	return true;

    case PrefsCmd:
	if (Unlock_CheckKey())
	    PrefsForm_Run();
	return true;

    case SetPasswdCmd:
	if (App_CheckReadOnly())
	    return true;
	SetPasswd_Run();
	return true;
    }

    return false;
}

static Err CheckROMVersion (void)
{
    UInt32 romVersion;
    /* See if we have at least the minimum required version of the 
     * ROM or later.
     */
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion < sysMakeROMVersion(3, 0, 0, sysROMStageRelease, 0)) {
	FrmCustomAlert(NotEnoughFeaturesAlert, "palmos 3.0", NULL, NULL);
	
	/* Pilot 1.0 will continuously relaunch this app unless we switch to 
	 * another safe one.
	 */
	if (romVersion < 0x02000000)
	    AppLaunchWithCommand(sysFileCDefaultApp, 
				 sysAppLaunchCmdNormalLaunch, NULL);
	return sysErrRomIncompatible;
    }

    return 0;
}


UInt32 PilotMain(UInt16 launchCode,
		 void *cmdPBP,
		 UInt16 UNUSED(launchFlags))
{
    struct EventType keyev;
    Err err = 0;

    if ((err = CheckROMVersion()))
	return err;

#ifdef NOTIFY_SLEEP_HANDLER
    if (launchCode == kKeyringResumeSleepLaunch) {
	/* We were relaunched by the sleep notify handler.
	 * Enqueue event to resume sleeping 
	 */
	keyev.eType = keyDownEvent;
	keyev.data.keyDown.chr = resumeSleepChr;
	keyev.data.keyDown.keyCode = 0;
	keyev.data.keyDown.modifiers = commandKeyMask;
	EvtAddEventToQueue(&keyev);

	/* Set launch code to normal */
	launchCode = sysAppLaunchCmdNormalLaunch;
    }
#endif

    switch (launchCode)
    {
    case sysAppLaunchCmdNormalLaunch:	    
	err = App_Start();
	if (!err) {
	    FrmGotoForm(ListForm);
	    App_EventLoop();
	    App_Stop();
	}
	break;

    case sysAppLaunchCmdFind:
	Search((FindParamsPtr) cmdPBP, 
	       launchFlags & (sysAppLaunchFlagNewGlobals 
			      | sysAppLaunchFlagSubCall));
	break;

    case sysAppLaunchCmdGoTo:
	{
	    Boolean launched = launchFlags & sysAppLaunchFlagNewGlobals;
	    UInt16 recordNum = ((GoToParamsPtr) cmdPBP)->recordNum;

	    if (launched)
	    {
		err = App_Start();
		if (err)
		    return err;
	    }

	    KeyEdit_GotoRecord(recordNum);
	    if (launched) {
		App_EventLoop();
		App_Stop();
	    }
	}
	break;

    case sysAppLaunchCmdSystemLock:
    case sysAppLaunchCmdTimeChange:	    
	/* Lock application on System Lock or when someone manipulates
	 * the time.
	 */
	Snib_Eradicate ();
	break;
	
    case sysAppLaunchCmdAlarmTriggered:	    

	/* This is the expiry alarm, or the time changed */
	Snib_Eradicate ();
	if ((launchFlags & sysAppLaunchFlagSubCall) && gSleeping) {
	    /* We were sleeping before alarm occured.  Enqueue an
	     * AutoOff character to go to sleeping mode again.  This
	     * will also close the key edit form.
	     */
	    keyev.eType = keyDownEvent;
	    keyev.data.keyDown.chr = vchrAutoOff;
	    keyev.data.keyDown.keyCode = 0;
	    keyev.data.keyDown.modifiers = commandKeyMask;
	    EvtAddEventToQueue(&keyev);
	}
	break;

    case sysAppLaunchCmdSaveData:
        FrmSaveAllForms ();
        break;
    }

    return err;
}



Boolean App_CheckReadOnly(void)
{
     if (g_ReadOnly)
          FrmAlert(ReadOnlyAlert);
     return g_ReadOnly;
}

