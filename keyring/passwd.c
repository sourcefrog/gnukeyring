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

static Boolean UnlockForm_HandleEvent(EventPtr event)
{
    if (event->eType == ctlSelectEvent
	&& event->data.ctlSelect.controlID == VeilPasswordCheck) {
	FldSetFont(UI_GetObjectByID(FrmGetActiveForm(), MasterKeyFld), 
		   event->data.ctlSelect.on ? fntStar : fntPassword);
	return true;
    }
    return false;
}

static Boolean UnlockForm_Run(UInt8 *keyHash) {
    UInt16 	result;
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(UnlockForm);
    Char * 	entry;
    Boolean	done, correct;
    Boolean	veil = true;
    Int16	size = sizeof(veil);
    Err         err;
    Int16       len;

    PrefGetAppPreferences(kKeyringCreatorID, prefID_VeilPassword,
			  &veil, &size, true);

    CtlSetValue(UI_GetObjectByID(frm, VeilPasswordCheck), veil);
    FldSetFont(UI_GetObjectByID(frm, MasterKeyFld), 
	       veil ? fntStar : fntPassword);

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
		err = EncDigestMD5(entry, len, keyHash);
		MemSet(entry, len, ' ');
		if (err) {
		    UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);
		    correct = false;
		} else {
		    Snib_StoreRecordKey(keyHash);
		}
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
Boolean Unlock_GetKey(Boolean askAlways, UInt8 *key)
{
    /* First try to get the cached key */
    if (!askAlways && Snib_RetrieveKey(key))
	return true;
    return UnlockForm_Run(key);
}

Boolean Unlock_CheckKey(void)
{
     UInt8    dummy[k2DESKeySize];
     Boolean  result;

     result = Unlock_GetKey(false, dummy);
     MemSet(dummy, k2DESKeySize, 0);
     return result;
}

