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

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "dbutil.h"

void DB_WriteStringFromHandle(void *dest, UInt32 *off, MemHandle h, UInt32 len) {
    if (h) {
	Char * p = MemHandleLock(h);
	DmWrite(dest, *off, p, len);
	*off += len;
	MemHandleUnlock(h);
    } else {
	DmWrite(dest, *off, "", 1);
	(*off)++;
    }
}


/* Write a string into a database record, and update a position pointer. */
void DB_WriteString(void *dest, UInt32 *off, Char const *str) {
    UInt16 len;

    len = StrLen(str);
    DmWrite(dest, *off, str, len);
    *off += len;
}