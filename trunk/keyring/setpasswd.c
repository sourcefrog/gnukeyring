/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2001-2005 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

#define DEFAULT_ITER 500
#define DEFAULT_CIPHER AES_128_CBC_CIPHER

static const Int16 iterMap[] = {
    50,   Iter50Push,
    100,  Iter100Push,
    250,  Iter250Push,
    500,  Iter500Push,
    1000, Iter1000Push,
    -1
};

static const Int16 cipherMap[] = {
    NO_CIPHER, CipherNoPush,
    DES3_EDE_CBC_CIPHER, CipherDESPush,
    AES_128_CBC_CIPHER, CipherAES128Push,
    AES_256_CBC_CIPHER, CipherAES256Push,
    -1
};


/* Set Password dialog
 *
 * TODO: Perhaps show a caution if the master password is less than
 * (say) five characters.
 *
 * TODO: "Generate" button when setting master password.
 */

/* Return a locked MemPtr to the entered password or NULL if cancelled. */
GUI_SECTION 
Char *SetPasswd_Ask(UInt16 *pCipher, UInt16 *pIter)
{
    FormPtr 	prevFrm = FrmGetActiveForm();
    FormPtr	frm;
    UInt16 	btn;
    int         cipher, iter;
    Boolean 	match;
    FieldPtr 	masterFld, confirmFld;
    MemHandle   handle;
    MemPtr      result = NULL;
    UInt32      encoding;
    KrAppInfoPtr appInfoPtr;
    Char *masterPtr, *confirmPtr;

    frm = FrmInitForm(SetPasswdForm);
    FrmSetActiveForm(frm);
    masterFld = UI_GetObjectByID(frm, MasterKeyFld);
    confirmFld = UI_GetObjectByID(frm, ConfirmFld); 

    if (FtrGet(sysFtrCreator, sysFtrNumEncoding, &encoding))
	/* if feature not found it is palm latin */
	encoding = charEncodingPalmLatin;

    /* Change to Password font if encoding is not latin and 
     * we use custom fonts. */
    if (gPrefs.useCustomFonts && encoding == charEncodingPalmLatin) {
	FldSetFont(masterFld, fntPassword);
	FldSetFont(confirmFld, fntPassword);
    }

    iter = DEFAULT_ITER;
    cipher = DEFAULT_CIPHER;
    if (gKeyDB && (appInfoPtr = KeyDB_LockAppInfo())) {
	if (MemPtrSize(appInfoPtr) > 
	    sizeof(AppInfoType) + sizeof(SaltHashType)) {
	    iter = appInfoPtr->keyHash.iter;
	    cipher = appInfoPtr->keyHash.cipher;
	}
	MemPtrUnlock(appInfoPtr);
    }
    UI_ScanAndSet(frm, iterMap, iter);
    UI_ScanAndSet(frm, cipherMap, cipher);
       
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

    iter = UI_ScanForFirst(frm, iterMap);
    if (iter < 0)
	iter = DEFAULT_ITER;
    cipher = UI_ScanForFirst(frm, cipherMap);
    if (cipher < 0)
	cipher = DEFAULT_CIPHER;
    *pIter = iter;
    *pCipher = cipher;
    
 leave:

    /* Eradicate anything that contains clear text passwords or
     * the hash. 
     */
    handle = FldGetTextHandle(masterFld);
    if (handle) {
	 MemWipe(MemHandleLock(handle), MemHandleSize(handle));
	 MemHandleUnlock(handle);
    }
    FldSetTextHandle(masterFld, handle);
    handle = FldGetTextHandle(confirmFld);
    if (handle) {
	 MemWipe(MemHandleLock(handle), MemHandleSize(handle));
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
 * Afterwards this routine must do two things: re-encrypt the session key 
 * and store it back, and store a check hash of the new password.
 *
 * Returns true if successfull.
 */
REENCRYPT_SECTION 
Boolean SetPasswd_Run(void)
{
    CryptoKey  *oldKey;
    Char *      newPasswd;
    UInt16      cipher, iter;

    oldKey = MemPtrNew(sizeof(CryptoKey));
    if (!Unlock_GetKey(true, oldKey)) {
	MemPtrFree(oldKey);
	return false;
    }

    newPasswd = SetPasswd_Ask(&cipher, &iter);

    /* Check whether user cancelled new password dialog */
    if (newPasswd == NULL) {
	CryptoDeleteKey(oldKey);
	MemPtrFree(oldKey);
	return false;
    }

    /* This stores the checking-hash and also reencrypts and stores
     * the session key.
     */
    SetPasswd_Reencrypt(oldKey, newPasswd, cipher, iter);

    /* Eradicate the new and old passwords.
     */
    MemWipe(newPasswd, StrLen(newPasswd));
    CryptoDeleteKey(oldKey);
    MemPtrFree(oldKey);

    MemPtrFree(newPasswd);
    return true;
}
