/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * GNU Tiny Keyring for PalmOS -- store passwords securely on a handheld
 * Copyright (C) 1999 Martin Pool
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

#define kKeyDBType		'Gkyr'
#define kKeyDBName		"Keys-Gtkr"
#define kKeyringCreatorID	'Gtkr'

/* This is a hex representation of the version number where the
 * database format last changed -- not necessarily the version of the
 * app. */
#define kKeyringVersion		0x0042

#define kLockExpiryPref		0
#define kGeneralPref		1
#define kGeneratePref		2

#define kPasswdHashSize		16

#define kNoRecord		((UInt) 0xffff)

#define kBlockSize		8

// in-memory unpacked form of a key record
typedef struct {
    /* Length of corresponding string fields. */
    ULong nameLen, acctLen, passwdLen, notesLen;
    /* Handles to string values, or 0 */
    VoidHand nameHandle, acctHandle, passwdHandle, notesHandle;

    /* Date password was last changed. */
    DateType lastChange;

    /* Last change date has been modified? */
    Boolean lastChangeDirty;
} UnpackedKeyType;

typedef UnpackedKeyType *UnpackedKeyPtr;


/* Application info */
typedef struct {
    ULong 	passwdSalt;
    Byte 	passwdHash[16];

    Word 	appInfoVersion;
} KeyringInfoType;
typedef KeyringInfoType *KeyringInfoPtr;


typedef struct {
    ULong timeoutSecs;
} KeyringPrefsType;

typedef KeyringPrefsType *KeyringPrefsPtr;

Boolean Common_HandleMenuEvent(EventPtr event);

void App_AboutCmd(void);
void App_NotImplemented(void);
void App_ReportSysError(const CharPtr func, int err);
void App_SavePrefs(void);

extern DmOpenRef gKeyDB;
extern UInt gKeyRecordIndex;
extern Byte gRecordKey[kPasswdHashSize];
extern KeyringPrefsType gPrefs;

#define UNUSED __attribute__((unused))