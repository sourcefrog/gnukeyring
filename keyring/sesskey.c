/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; indent-tabs-mode: t; -*-
 *
 * $Id$
 * 
 * GNU Keyring for PalmOS -- store passwords securely on a handheld
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
#include "memutil.h"
#include "crypto.h"
#include "resource.h"
#include "sesskey.h"


/* If the keyring is unlocked, this holds the hash of the master
 * password, which is used for the two DES keys to decrypt records. */
UInt8		gRecordKey[kRecordKeySize];



/*
 * Store the in-memory session key back into the database, encrypted
 * by the specified master password.
 *
 * This function works whether the database is empty or not, so it can be
 * called for a new database after generating a new session key and setting
 * the master password.
 */
void SessKey_Store(Char *UNUSED(newPasswd))
{
}


/*
 * Make up a new session key.  This is called only when creating a new
 * database -- calling it any other time will make the database
 * unreadable.  It's left in memory in gRecordKey, and can later be saved
 * using SessKey_Store.
 */
void SessKey_Generate(void)
{
    MemSet(gRecordKey, kRecordKeySize, 0);
}


/*
 * Load in the session key from the database and decrypt it.
 */
void SessKey_Load(Char *UNUSED(passwd))
{
    MemSet(gRecordKey, kRecordKeySize, 0);    
}
