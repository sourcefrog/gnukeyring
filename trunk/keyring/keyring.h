/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@users.sourceforge.net>
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

#ifdef __GNUC__
#  define UNUSED(x) x __attribute__((unused))
#endif	/* !__GNUC__ */


#define kKeyDBType		'Gkyr'
#define kKeyDBName		"Keys-Gtkr"
#define kKeyringCreatorID	'Gtkr'
#define kAppName		"Keyring"
#define kKeyDBTempName          "Keys-Gtkr-tmp"
#define kKeyDBTempType          'ktmp'

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
 * quite similar to v1.  
 *
 * v5 has completely new encryption format.  All kind of meta-information
 * resides in the AppInfo, including the key.  See HACKING for details.
 */
#define kDatabaseVersion	5

#define kLockExpiryPref		0
#define kGeneralPref		1
#define kGeneratePref		2
#define kLastVersionPref        3
#define prefID_ReadOnlyAccepted 4
#define prefID_VeilPassword     5

#define kKeyringResumeSleepLaunch sysAppLaunchCmdCustomBase


#define kNumHiddenRecs 0
#define kNoRecord		((UInt16) -1)


/*
 * Keyring types, see HACKING.
 */


/* FieldTypes */
#define StrFieldType   0
#define PwFieldType    1
#define DateFieldType  2
#define TANFieldType   3
#define OTPFieldType   4

#define NotesFieldID 255


/*
 * The ciphers.  Currently only triple DES is defined.
 */
#define NO_CIPHER           0
#define DES3_EDE_CBC_CIPHER 1
#define AES_128_CBC_CIPHER  2
#define AES_256_CBC_CIPHER  3


/* The Snib contains a crypto key that will be used to encrypt and
 * decrypt the records.
 */
typedef struct {
    union {
	des_cblock des[3];
	unsigned char aes[32];
    } key;
} SnibType;
#define kSnibSize  sizeof(SnibType)

/* The salt; used to prevent dictionary attacks */
#define kSaltSize  8
typedef UInt8      SaltType[kSaltSize];

/* The key hash; used to check password */
#define kHashSize  8
typedef UInt8      HashType[kHashSize];

typedef struct {
    SaltType salt;
    UInt16   iter;
    UInt16   cipher;
    HashType hash;
} SaltHashType;

/* The additional information we need for each category */
typedef struct {
    /* Remember the last used template. */
    UInt8  lastTemplate;
} KrCatInfoType;

typedef struct {
    Char   label[16];    /* User defined label text     */
    UInt8  fieldType;    /* fieldType 0:Text 1:Password 2:Modified-Date 3:OP*/
    UInt8  defaultFont;  /* font to use for value field */
} KrLabelType;

typedef struct {
    UInt32  timeoutSecs;
    UInt16  category;
    Boolean useCustomFonts;
    Boolean keepSnibWhileBusy;
} KeyringPrefsType, *KeyringPrefsPtr;

typedef struct {
    AppInfoType    categoryInfo;
    SaltHashType   keyHash;
#ifdef SUPPPORT_TEMPLATES
    UInt8          numberOfLabels;
    UInt8          numberOfTemplates;
    KrCatInfoType  krCatInfo[dmRecNumCategories];
#endif
} KrAppInfoType, *KrAppInfoPtr;

#define KrLabels(appInfoPtr) ((KrLabelType *) (appInfoPtr+1))

enum updateCodes {
    updateCategory = 1
};
