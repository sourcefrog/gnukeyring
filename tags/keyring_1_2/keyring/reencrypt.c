/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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

/*
 * TODO: Instead of unpacking and re-packing, just convert each
 * encrypted block in place.  There's a little complication to skip
 * the public name, but it's otherwise probably simpler and certainly
 * quicker.
 */


/*
 * Walk through the database, and for each record decrypt it using the
 * old session key from the snib, and then store it back encrypted by
 * the new session key.  Finally update the snib to hold the hash of
 * the new password.
 *
 * We now no longer bother unpacking each record, but rather make a
 * single pass through converting packed record.  This is simpler and
 * saves space.
 *
 * We do have to also include archived records, as they must be
 * accessible on the PC.
 */
void KeyDB_Reencrypt(CryptoKey oldRecordKey, Char const *newPasswd)
{
    /* We read each record into memory, decrypt it using the old
     * unlock hash, then encrypt it using the new hash and write it
     * back. */
    UInt16 	numRecs = DmNumRecords(gKeyDB);
    UInt16 	idx;
    MemHandle   recHand;
    void	*recPtr;
    UInt16	attr;
    Err		err;
    UnpackedKeyType	unpacked;
    UInt8	keyMD5sum[kMD5HashSize];
    CryptoKey	newRecordKey;

    MD5((void *) newPasswd, StrLen(newPasswd), keyMD5sum);
    CryptoPrepareKey(keyMD5sum, newRecordKey);
    MemSet(keyMD5sum, sizeof(keyMD5sum), 0);

    for (idx = kNumHiddenRecs; idx < numRecs; idx++) {
	// Skip deleted records.  Handling of archived records is a
	// bit of an open question, because we'll still want to be
	// able to decrypt them on the PC.  (If we can ever do
	// that...)
	err = DmRecordInfo(gKeyDB, idx, &attr, NULL, NULL);
	ErrFatalDisplayIf(err, "DmRecordInfo");
	if (attr & (dmRecAttrDelete | dmRecAttrSecret))
	    continue;

	// Open read-only and read in to memory
	recHand = DmGetRecord(gKeyDB, idx);
        if (!recHand) {
             UI_ReportSysError2(ID_KeyDatabaseAlert, DmGetLastErr(),
                                __FUNCTION__ ": DmGetRecord");
             continue;
        }
        recPtr = MemHandleLock(recHand);
	Keys_UnpackRecord(recPtr, &unpacked, oldRecordKey);
        MemHandleUnlock(recHand);
        Keys_SaveRecord(&unpacked, idx, newRecordKey);
	err = DmReleaseRecord(gKeyDB, idx, true);
	ErrFatalDisplayIf(err, "DmReleaseRecord");

	UnpackedKey_Free(&unpacked);
    }
    MemSet(newRecordKey, sizeof(newRecordKey), 0);
}


