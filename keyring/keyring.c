/* -*- c-basic-offset: 4; c-file-style: java; -*-
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

// ======================================================================
// Globals

KeyringPrefsType gPrefs;

Boolean gEditFormActive;
Boolean gSleeping;


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
    
    version = PrefGetAppPreferences(kKeyringCreatorID,
				    kGeneralPref,
				    &gPrefs, &size,
				    (Boolean) true);

#ifdef BETA
    /* If this is a beta version and it previous version was different
     * give a alarm.
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



static Err App_Start(void)
{
    Err err;

    handleFontStar = DmGetResource('NFNT', StarFont);
    FntDefineFont(fntStar, (FontPtr)MemHandleLock(handleFontStar));
    handleFontPW = DmGetResource('NFNT', PasswordFont);
    FntDefineFont(fntPassword, (FontPtr)MemHandleLock(handleFontPW));

    App_LoadPrefs();

    if ((err = Snib_Init()))
	return err;

    if ((err = KeyDB_Init()))
        return err;

    Secrand_Init();
    FrmGotoForm(ListForm);
    
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

    MemHandleUnlock(handleFontStar);
    DmReleaseResource(handleFontStar);
    MemHandleUnlock(handleFontPW);
    DmReleaseResource(handleFontPW);
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
	Secrand_AddEventRandomness(&event);

	if (event.eType == keyDownEvent) {
	    if (event.data.keyDown.chr == vchrAutoOff
		|| event.data.keyDown.chr == vchrPowerOff
		|| event.data.keyDown.chr == vchrLock) {
		gSleeping = true;
		if (gEditFormActive && 
		    (event.data.keyDown.chr == vchrLock
		     || Snib_GetSnib(false) == NULL)) {
		    FrmSaveAllForms();
		    FrmCloseAllForms();
		    FrmGotoForm(ListForm);
		}
	    }
	} else if (event.eType != nilEvent)
	    gSleeping = false;
	
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

    case ID_PrefsCmd:
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


static Err RomVersionCompatible (void)
{
    UInt32 romVersion;
    UInt32 encryption = 0;

    // See if we have at least the minimum required version of the ROM or later.
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    FtrGet(sysFtrCreator, sysFtrNumEncryption, &encryption);
    if (romVersion < sysMakeROMVersion(3, 0, 0, sysROMStageRelease, 0)
	|| (encryption & sysFtrNumEncryptionMaskDES) == 0) {
	FrmAlert(NotEnoughFeaturesAlert);
	
	// Pilot 1.0 will continuously relaunch this app unless we switch to 
	// another safe one.
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

    if ((err = RomVersionCompatible()))
	return err;

#if 0
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
	    App_EventLoop();
	    App_Stop();
	}
	break;

    case sysAppLaunchCmdFind:
	Search((FindParamsPtr) cmdPBP);
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

	    KeyEditForm_GotoRecord(recordNum);
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
	    /* We were relaunched by the sleep notify handler.
	     * Enqueue event to resume sleeping 
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
          FrmAlert(alertID_ReadOnly);
     return g_ReadOnly;
}

