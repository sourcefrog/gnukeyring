/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 *
 * $Id$
 *
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
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
#include "memutil.h"


static UInt32		gExpiry;

// ======================================================================
// Unlock form


/* Store the hash of an entered correct password for later use in
 * decoding records. */
static void Unlock_SetKey(Char const *passwd) {
    Err		err;

    if (!passwd)
	passwd = "";

    err = EncDigestMD5((void *) passwd, StrLen(passwd), gRecordKey);
    if (err)
	App_ReportSysError(CryptoErrorAlert, err);
}


#ifdef REALLY_OBLITERATE
static void Unlock_ObliterateKey(void) {
    MemSet(gRecordKey, kPasswdHashSize, 'x');
}
#endif


void Unlock_Reset(void) {
  gExpiry = 0;
}


void Unlock_PrimeTimer(void) {
    gExpiry = TimGetSeconds() + gPrefs.timeoutSecs;
}


Boolean UnlockForm_Run() {
    UInt16 	result;
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm = FrmInitForm(UnlockForm);
    Char * 	entry;
    UInt16 	entryIdx = FrmGetObjectIndex(frm, MasterKeyFld);
    FieldPtr 	entryFld = FrmGetObjectPtr(frm, entryIdx);
    Boolean 	done, correct;

    do { 
	FrmSetFocus(frm, entryIdx);
	result = FrmDoDialog(frm);

	if (result == UnlockBtn) {
	    entry = FldGetTextPtr(entryFld);
	    if (!entry)
		entry = "";
	    done = correct = KeyDB_Verify(entry);

	    if (correct) {
		Unlock_PrimeTimer();
		Unlock_SetKey(entry);
	    } else {
		FrmAlert(WrongKeyAlert);
	    }
	} else {
	    done = true;
	    correct = false;
	} 
    } while (!done);

    Mem_ObliterateHandle((MemHandle) FldGetTextHandle(entryFld));
    FrmDeleteForm(frm);
    FrmSetActiveForm(prevFrm);

    return correct;
}


/* Check whether a previously entered password is still valid. */
Boolean Unlock_CheckTimeout() {
    UInt32 now = TimGetSeconds();

    if (now > gExpiry) {
#ifdef REALLY_OBLITERATE
	Unlock_ObliterateKey();
#endif
	return false;
    }

    // If the timeout is too far in the future, then adjust it: this
    // makes it work OK if e.g. the clock has changed.
    if (now + gPrefs.timeoutSecs < gExpiry)
	gExpiry = now + gPrefs.timeoutSecs;

    return true;
}




// ======================================================================
// Set password


/* Return true if set, false if cancelled. */
Boolean SetPasswd_Run(void) {
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm;
    UInt16 	btn;
    Boolean 	match, result=false;
    FieldPtr 	masterFld, confirmFld;
    Char *masterPtr, *confirmPtr;

    frm = FrmInitForm(SetPasswdForm);
    FrmSetActiveForm(frm);
    masterFld = UI_GetObjectByID(frm, MasterKeyFld);
    confirmFld = UI_GetObjectByID(frm, ConfirmFld); 
    FrmSetFocus(frm, FrmGetObjectIndex(frm, MasterKeyFld)); 
   
 doDialog:	
    btn = FrmDoDialog(frm);
    if (btn != OkBtn)
	goto leave;

    masterPtr = FldGetTextPtr(masterFld);
    if (!masterPtr) masterPtr = "";
    
    confirmPtr = FldGetTextPtr(confirmFld);
    if (!confirmPtr) confirmPtr = "";
    
    match = !StrCompare(masterPtr, confirmPtr);
    if (!match) {
	FrmAlert(PasswdMismatchAlert);
	goto doDialog;
    }

    // TODO: Instead of copying, pull the handle out of the field and
    // give it a null handle.  Also do this to the confirm field.
    // When we're done with both of them, scribble over them and then
    // free the handles.  This is not completely safe but it should
    // help.  We could improve the odds by preallocating the handles
    // to be bigger than any password the user could enter.

    // We need to keep a copy of the password, because the field
    // object containing it will be freed before we finish with it.
    masterPtr = MemPtrNew(StrLen(confirmPtr) + 1);
    ErrFatalDisplayIf(!masterPtr, __FUNCTION__ " out of memory");
    StrCopy(masterPtr, confirmPtr);

    // May as well release confirm form to free up memory
    FrmDeleteForm(frm);
    
    frm = FrmInitForm(BusyEncryptForm);
    FrmDrawForm(frm);

    KeyDB_SetPasswd(masterPtr);
#ifdef REALLY_OBLITERATE
    Mem_ObliteratePtr(masterPtr);
#endif /* REALLY_OBLITERATE */
    MemPtrFree(masterPtr);
    result = true;

    FrmEraseForm(frm);

 leave:
    FrmDeleteForm(frm);
    if (prevFrm)
	FrmSetActiveForm(prevFrm);
    return result;
}


