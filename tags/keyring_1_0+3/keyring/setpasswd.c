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

#include "keyring.h"
#include "record.h"
#include "passwd.h"
#include "resource.h"
#include "keydb.h"
#include "uiutil.h"

/* Set Password dialog
 *
 * TODO: Perhaps show a caution if the master password is less than
 * (say) five characters.
 *
 * TODO: "Generate" button when setting master password.
 */


/* Return true if set, false if cancelled. */
Boolean SetPasswd_Run(void)
{
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

    /* This stores the checking-hash and also reencrypts and stores
     * the session key. */
    KeyDB_SetPasswd(masterPtr);
    
    MemPtrFree(masterPtr);
    
    result = true;

    FrmEraseForm(frm);

 leave:
    FrmDeleteForm(frm);
    if (prevFrm)
	FrmSetActiveForm(prevFrm);
    return result;
}
