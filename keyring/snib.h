/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
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


/* gRecordKey contains a DES3-EDE key that will be used to encrypt and
 * decrypt the records.  It's read out of the hidden record when the
 * user's password is entered, but is lost again on exiting the
 * application.
 *
 * Eventually we will store this in a database marked not-for-backup,
 * so that people will be able to switch apps without needing to log
 * in again.  But we don't do that yet. */

Err Snib_Init(void);

void Snib_StoreRecordKey(UInt8 *newHash);
Boolean Snib_RetrieveKey(UInt8* keyHash);

/*
 * There is only one record in this database, and it contains this
 * structure.
 */
typedef struct {
    UInt32    expiryTime;
    UInt8     recordKey[k2DESKeySize];
} SnibStruct, *SnibPtr;

void Snib_Eradicate(void);
