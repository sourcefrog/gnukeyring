/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@users.sourceforge.net>
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

/* Set Password dialog
 *
 * TODO: Perhaps show a caution if the master password is less than
 * (say) five characters.
 *
 * TODO: "Generate" button when setting master password.
 */

/* Return a locked MemPtr to the entered password or NULL if cancelled. */
Char * SetPasswd_Ask(void)
{
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm;
    UInt16 	btn;
    Boolean 	match;
    FieldPtr 	masterFld, confirmFld;
    MemHandle   handle;
    MemPtr      result = NULL;
    UInt32      encoding;
    Char *masterPtr, *confirmPtr;

    frm = FrmInitForm(SetPasswdForm);
    FrmSetActiveForm(frm);
    masterFld = UI_GetObjectByID(frm, MasterKeyFld);
    confirmFld = UI_GetObjectByID(frm, ConfirmFld); 

    if (FtrGet(sysFtrCreator, sysFtrNumEncoding, &encoding))
	/* if feature not found it is palm latin */
	encoding = charEncodingPalmLatin;

    /* If encoding is not latin, use default system fonts. */
    if (encoding == charEncodingPalmLatin) {
	FldSetFont(masterFld, fntPassword);
	FldSetFont(confirmFld, fntPassword);
    }
    
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

    /* Copy the master password in a locked MemPtr. 
     * I hate copying confidential information around,
     * but a locked Pointer can't move, so it should be save.
     */
    result = MemPtrNew(StrLen(masterPtr) + 1);
    StrCopy(result, masterPtr);

 leave:

    /* Eradicate anything that contains clear text passwords or
     * the hash. 
     */
    handle = FldGetTextHandle(masterFld);
    if (handle) {
	 MemSet(MemHandleLock(handle), MemHandleSize(handle), 0);
	 MemHandleUnlock(handle);
    }
    FldSetTextHandle(masterFld, handle);
    handle = FldGetTextHandle(confirmFld);
    if (handle) {
	 MemSet(MemHandleLock(handle), MemHandleSize(handle), 0);
	 MemHandleUnlock(handle);
    }
    FldSetTextHandle(confirmFld, handle);

    FrmEraseForm(frm);
    FrmDeleteForm(frm);
    if (prevFrm)
	FrmSetActiveForm(prevFrm);
    return (Char *) result;
}

/*
 * Set the master password for the database.  This authorizes the user,
 * asks him user to enter a new password. 
 *
 * Aftewards this routine must do two things: re-encrypt the session key 
 * and store it back, and store a check hash of the new password.
 *
 * Returns true if successfull.
 */
Boolean SetPasswd_Run(void)
{
    CryptoKey   oldKey;
    Char *      newPasswd;
    FormPtr	frm, oldFrm;

    if (!Unlock_GetKey(true, oldKey))
	 return false;

    newPasswd = SetPasswd_Ask();

    /* Check whether user cancelled new password dialog */
    if (newPasswd == NULL)
	return false;

    /* This stores the checking-hash and also reencrypts and stores
     * the session key.
     */
    oldFrm = FrmGetActiveForm();
    frm = FrmInitForm(BusyEncryptForm);
    FrmSetActiveForm(frm);
    FrmDrawForm(frm);
    KeyDB_Reencrypt(oldKey, newPasswd);
    PwHash_Store(newPasswd);
    FrmEraseForm(frm);
    FrmDeleteForm(frm);
    if (oldFrm)
	FrmSetActiveForm(oldFrm);

    /* Eradicate the new and old passwords.
     */
    MemSet(newPasswd, StrLen(newPasswd), 0);
    MemSet(oldKey, sizeof(oldKey), 0);

    MemPtrFree(newPasswd);
    return true;
}
