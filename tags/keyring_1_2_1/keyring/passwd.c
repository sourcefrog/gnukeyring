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

// ======================================================================
// Unlock form

static void UnlockForm_SetFont(FormPtr frm, Boolean veil) {
    FontID font;
    UInt32 romVersion;
    if (veil) {
	font = gPrefs.useCustomFonts ? fntStar : symbolFont;
    } else {
	UInt32 encoding;
	if (FtrGet(sysFtrCreator, sysFtrNumEncoding, &encoding))
	    /* if feature not found it is palm latin */
	    encoding = charEncodingPalmLatin;

	/* Check if we should use custom fonts. */
	if (gPrefs.useCustomFonts && encoding == charEncodingPalmLatin)
	    font = fntPassword;
	else
	    font = stdFont;
    }
    FtrGet(sysFtrCreator, sysFtrNumROMVersion, &romVersion);
    if (romVersion < sysMakeROMVersion(3, 5, 0, sysROMStageRelease, 0)) {
	/* Work around a nasty bug in older palm versions */
	FieldPtr field = (FieldPtr) UI_GetObjectByID(frm, MasterKeyFld);
	MemHandle text = FldGetTextHandle(field);
	UInt16  offset = 0, len = 0, inspt = 0;
	if (text) {
	    char *start = MemHandleLock(text);
	    offset = FldGetTextPtr(field) - start;
	    len = FldGetTextLength(field);
	    inspt = FldGetInsPtPosition(field);
	    MemHandleUnlock(text);
	    FldSetTextHandle(field, NULL);
	}
	FldSetFont(field, font);
	if (text) {
	    FldSetText(field, text, offset, len);
	    FldSetInsertionPoint(field, inspt);
	    if (FrmVisible(frm))
		FldDrawField(field);
	}
    } else
	FldSetFont(UI_GetObjectByID(frm, MasterKeyFld), font);
}



static Boolean UnlockForm_HandleEvent(EventPtr event)
{
    if (event->eType == ctlSelectEvent
	&& event->data.ctlSelect.controlID == VeilPasswordCheck) {
	UnlockForm_SetFont(FrmGetActiveForm(), event->data.ctlSelect.on);
	return true;
    }
    return false;
}

static Boolean UnlockForm_Run(CryptoKey cryptoKey) {
    UInt16 	result;
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(UnlockForm);
    Char * 	entry;
    Boolean	done, correct;
    Boolean	veil = true;
    Int16	size = sizeof(veil);
    Int16       len;
    UInt8       keyHash[kMD5HashSize];

    PrefGetAppPreferences(kKeyringCreatorID, prefID_VeilPassword,
			  &veil, &size, true);

    CtlSetValue(UI_GetObjectByID(frm, VeilPasswordCheck), veil);
    UnlockForm_SetFont(frm, veil);
    FrmSetEventHandler(frm, UnlockForm_HandleEvent);

    do { 

	FrmSetFocus(frm, FrmGetObjectIndex(frm, MasterKeyFld));
	result = FrmDoDialog(frm);

	if (result == UnlockBtn) {
	    entry = FldGetTextPtr(UI_GetObjectByID(frm, MasterKeyFld));
	    if (!entry)
		entry = "";
	    done = correct = PwHash_Check(entry);

	    if (correct) {
		len = StrLen(entry);
		MD5(entry, len, keyHash);
		MemSet(entry, len, ' ');
		Snib_StoreRecordKey(keyHash);
		if (cryptoKey)
		    CryptoPrepareKey(keyHash, cryptoKey);
		MemSet(keyHash, sizeof(keyHash), 0);
	    } else {
		FrmAlert(WrongKeyAlert);
	    }
	} else {
	    done = true;
	    correct = false;
	} 
    } while (!done);

    veil = CtlGetValue(UI_GetObjectByID(frm, VeilPasswordCheck));
    PrefSetAppPreferences(kKeyringCreatorID, prefID_VeilPassword, 0,
			  &veil, sizeof(veil), true);
    FrmDeleteForm(frm);
    FrmSetActiveForm(prevFrm);
    return correct;
}


/* Get the encryption key, or return false if the user declined to
 * enter the master password. */
Boolean Unlock_GetKey(Boolean askAlways, CryptoKey key)
{
    /* First try to get the cached key */
    if (!askAlways && Snib_RetrieveKey(key))
	return true;
    return UnlockForm_Run(key);
}

Boolean Unlock_CheckKey(void)
{
     Boolean  result;

     result = Unlock_GetKey(false, NULL);
     return result;
}

