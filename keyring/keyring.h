/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@users.sourceforge.net>
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
#define kAppName		"Keyring"

/* The database version we use:
 *
 * v0 had the checking hash stored in the AppInfo block, and could not
 * support Categories
 *
 * v1 had the session key stored in the SortInfo block, which was a
 * mistake.  Records are encrypted by the MD5 hash of the master
 * password.
 *
 * v2 was in 0.13.0pr1 [NOT SUPPORTED]
 *
 * v3 has the session key and master password checksum stored in
 * hidden records [NOT SUPPORTED].
 *
 * v4 has the master password checking hash stored in record 0
 * and encrypts using the direct hash of the master password.  This is
 * quite similar to v1.  */
#define kDatabaseVersion	4

/* The app and preferences version */
#define kAppVersion		0x1005

#define kLockExpiryPref		0
#define kGeneralPref		1
#define kGeneratePref		2
#define kLastVersionPref        3
#define prefID_ReadOnlyAccepted 4
#define prefID_VeilPassword     5

#define kKeyringResumeSleepLaunch sysAppLaunchCmdCustomBase


#define kMaxRecords             2000

#define kNoRecord		((UInt16) -1)

typedef struct {
    UInt32		timeoutSecs;
    UInt16		category;
} KeyringPrefsType;

typedef KeyringPrefsType *KeyringPrefsPtr;

Boolean Common_HandleMenuEvent(EventPtr event);

void App_AboutCmd(void);
void App_SavePrefs(void);

/*
 * All current preferences.  Read in at application startup, and
 * written out when they change.
 */
extern KeyringPrefsType gPrefs;

enum updateCodes {
    updateCategory = 1
};
