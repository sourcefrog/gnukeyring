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

/*
 * One record in the database contains a salted hash of the password,
 * which we use to check whether the password is correct or not.  The
 * initial four bytes are a random salt, which is prepended to the password
 * before it is hashed:
 *
 * HASH = SALT . MD5(SALT . PASSWORD)
 *
 * There are two reasons for this: the main one is that we also use
 * the MD5 hash of the password to encrypt the session key, so we
 * obviously can't leave it lying around.  The second is that it would
 * make lookups in a dictionary of MD5 hashes just a little too easy
 * for anyone who had such a thing.
 *
 * The digest is always taken over a 64-byte buffer.  If necessary the
 * password is truncated.  If the password is shorter then after a
 * terminating NUL the remainder of the buffer is filled with the
 * byte 0xFE.
 */

#include <PalmOS.h>

#include "keyring.h"
#include "keydb.h"
#include "crypto.h"
#include "pwhash.h"
#include "secrand.h"
#include "resource.h"
#include "keydb.h"
#include "uiutil.h"
#include "auto.h"

#define kSaltSize		4 /* bytes */
#define kMessageBufSize		64


/*
 * Generate the hash of a password, using specified salt.
 */
static Err PwHash_Calculate(UInt8 *digest, UInt32 salt, Char *passwd)
{
    Err		err;
    UInt8	buffer[kMessageBufSize];

    /* Generate salt. */
    MemSet(buffer, kMessageBufSize, 0);
    MemMove(buffer, &salt, kSaltSize);
    
    StrNCopy(buffer + kSaltSize, passwd, kMessageBufSize - 1 - kSaltSize);

    err = EncDigestMD5(buffer, kMessageBufSize, digest);
    if (err) {
	MemSet(buffer, kMessageBufSize, 0);
	UI_ReportSysError2(CryptoErrorAlert, err, __FUNCTION__);
	return err;
    }

    return 0;
}



/*
 * Generate new salt, and calculate a checking-hash.  Store this in
 * kMasterHashRec.
 */
Err PwHash_Store(Char *newPasswd)
{
    Err			err;
    Char		digest[kMD5HashSize];
    MemHandle		recHandle;
    void		*recPtr;
    UInt32		salt;

    salt = Secrand_GetBits(32);

    PwHash_Calculate(digest, salt, newPasswd);

    recHandle = DmResizeRecord(gKeyDB, kMasterHashRec, sizeof (CheckHashType));
    if (!recHandle) {
	err = DmGetLastErr();
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return err;
    }

    recPtr = MemHandleLock(recHandle);

    DmWrite(recPtr, 0, &salt, kSaltSize);
    DmWrite(recPtr, kSaltSize, digest, kMD5HashSize);

    MemHandleUnlock(recHandle);

    DmReleaseRecord(gKeyDB, kMasterHashRec, true);

    return 0;
}


/*
 * Check whether GUESS is the correct password for the database.
 */
Boolean PwHash_Check(Char *guess)
{
    Char		digest[kMD5HashSize];
    MemHandle		recHandle;
    Boolean		result;
    Err			err;
    void		*recPtr;
    UInt32		salt;

    /* Retrieve the hash record. */
    recHandle = DmQueryRecord(gKeyDB, kMasterHashRec);
    if (!recHandle) {
	err = DmGetLastErr();
	UI_ReportSysError2(ID_KeyDatabaseAlert, err, __FUNCTION__);
	return false;
    }
    recPtr = MemHandleLock(recHandle);

    MemMove(&salt, recPtr, kSaltSize);
    PwHash_Calculate(digest, salt, guess);
    result = !MemCmp(digest, recPtr + kSaltSize, kMD5HashSize);
    
    MemHandleUnlock(recHandle);

    return result;
}


