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

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "keydb.h"
#include "passwd.h"
#include "uiutil.h"
#include "memutil.h"
#include "pwhash.h"
#include "crypto.h"
#include "snib.h"
#include "reencrypt.h"

// ======================================================================
// Unlock form

/*
 * TODO: Show only the most-recently-entered character.  Perhaps
 * we need a custom widget to do this?
 */


static FieldPtr    f_entryFld;




/*
 * Set the master password for the database.  This is called after the
 * user has entered a new password and it has been properly checked,
 * so all it has to do is the database updates.  This routine is also
 * called when we're setting the initial master password for a newly
 * created database.
 *
 * This routine must do two things: re-encrypt the session key and
 * store it back, and store a check hash of the new password.
 */
void KeyDB_SetPasswd(UInt8 *oldKey, Char *newPasswd)
{
     PwHash_Store(newPasswd);
     KeyDB_Reencrypt(oldKey, newPasswd);
}

static void UnlockForm_SelAll(void) {
    /* We'd like to select the entire contents of the form every time
     * it's shown, but FldSetSelection seems not to work so well if
     * the form is not displayed.  Is FldSetSelection incompatible
     * with FrmDoDialog? */

/*      Int16 len = FldGetTextLength(f_entryFld); */
/*      if (len) */
/*          FldSetSelection(f_entryFld, 0, len); */
}



static Boolean UnlockForm_Run(UInt8 *keyHash) {
    UInt16 	result;
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(UnlockForm);
    Char * 	entry;
    UInt16 	entryIdx = FrmGetObjectIndex(frm, MasterKeyFld);
    Boolean 	done, correct;
    Err         err;
    Int16       len;

    do { 
        f_entryFld = FrmGetObjectPtr(frm, entryIdx);

	FrmSetFocus(frm, entryIdx);
	result = FrmDoDialog(frm);

	if (result == UnlockBtn) {
	    entry = FldGetTextPtr(f_entryFld);
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
                UnlockForm_SelAll();
	    }
	} else {
	    done = true;
	    correct = false;
	} 
    } while (!done);

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
