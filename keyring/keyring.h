/* -*- mode: c; c-indentation-style: "k&r"; c-basic-offset: 4 -*-
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

#ifdef __GNUC__
#  define UNUSED(x) x __attribute__((unused))
#endif	/* !__GNUC__ */

#define kKeyDBType		'Gkyr'
#define kKeyDBName		"Keys-Gtkr"
#define kKeyringCreatorID	'Gtkr'
#define kAppName		"GNU Keyring"

/* The database version we use. */
#define kDatabaseVersion	1

/* The app and preferences version */
#define kAppVersion		66

#define kLockExpiryPref		0
#define kGeneralPref		1
#define kGeneratePref		2

#define kPasswdHashSize		16

#define kNoRecord		((UInt16) -1)

#define kBlockSize		8


/* Application info */
typedef struct {
    UInt32 	passwdSalt;
    Char 	passwdHash[16];

    /* THIS FIELD IS NO LONGER USED -- USE THE DATABASE VERSION INSTEAD! */
    UInt16 	appInfoVersion;
} KeyringInfoType;
typedef KeyringInfoType *KeyringInfoPtr;


typedef struct {
    UInt32		timeoutSecs;
    UInt16		category;
} KeyringPrefsType;

typedef KeyringPrefsType *KeyringPrefsPtr;

Boolean Common_HandleMenuEvent(EventPtr event);

void App_AboutCmd(void);
void App_NotImplemented(void);
void App_ReportSysError(UInt16 msgID, Err err);
void App_SavePrefs(void);

extern DmOpenRef gKeyDB;
extern UInt16 gKeyRecordIndex;
extern UInt8 gRecordKey[kPasswdHashSize];
extern KeyringPrefsType gPrefs;


enum updateCodes {
    updateCategory = 1
};
