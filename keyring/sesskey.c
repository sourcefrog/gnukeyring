/* -*- c-indentation-style: "bsd"; c-basic-offset: 4; -*-
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

#include "keyring.h"
#include "memutil.h"
#include "crypto.h"
#include "resource.h"
#include "snib.h"
#include "auto.h"
#include "uiutil.h"
#include "sesskey.h"


/*
 * Make up a new session key.  This is called only when creating a new
 * database -- calling it any other time will make the database
 * unreadable.  It's left in memory in gRecordKey, and can later be saved
 * using SessKey_Store.
 */
void SessKey_Generate(void)
{
    UInt8       tmpKey[kDES3KeySize];
    
    MemSet(tmpKey, kDES3KeySize, 0);
    Snib_SetSessKey(tmpKey);
}


/*
 * Load the session key from the main database, decrypt it, and store it in
 * the working database.
 */
void SessKey_Load(Char *UNUSED(passwd))
{
    SessKey_Generate();         /* stubbed out */
}


void SessKey_Store(Char *UNUSED(passwd))
{

}

