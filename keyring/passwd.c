/* -*- c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 *
 * $Id$
 *
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
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
#include "memutil.h"
#include "pwhash.h"
#include "crypto.h"
#include "sesskey.h"
#include "snib.h"

// ======================================================================
// Unlock form

/*
 * TODO: Show only the most-recently-entered character.  Perhaps
 * we need a custom widget to do this?
 */


static FieldPtr    f_entryFld;

void Unlock_Reset(void) {
    Snib_Eradicate();
}


void Unlock_PrimeTimer(void) {
    Snib_SetExpiry(TimGetSeconds() + gPrefs.timeoutSecs);
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


Boolean UnlockForm_Run(void) {
    UInt16 	result;
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(UnlockForm);
    Char * 	entry;
    UInt16 	entryIdx = FrmGetObjectIndex(frm, MasterKeyFld);
    Boolean 	done, correct;

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
		Unlock_PrimeTimer();
                SessKey_Load(entry);
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


/* Check whether a previously entered password is still valid. */
Boolean Unlock_CheckTimeout() {
    UInt32 now = TimGetSeconds();

    if (now > g_Snib->expiryTime) {
	return false;
    }

    // If the timeout is too far in the future, then adjust it: this
    // makes it work OK if e.g. the clock has changed.
    if (now + gPrefs.timeoutSecs < g_Snib->expiryTime)
	Snib_SetExpiry(now + gPrefs.timeoutSecs);

    return true;
}
