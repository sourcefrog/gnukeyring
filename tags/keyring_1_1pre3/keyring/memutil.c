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

// ======================================================================
// Memory and database management routines



/* Return handle of a new chunk containing a copy of the string at
 * SRCPTR, and also put the length of that string in *LEN.  If the string
 * is "", then return null.  The returned length does not include the
 * terminal NUL, but the allocated chunk does have space for it.
 *
 * Running out before remain should never happen unless there's a bug
 * in the decryption stuff. */
static MemHandle Mem_StrToHandle(Char * srcPtr, Int16 *remain, Int16 *len)
{
    MemHandle h;
    Char* destPtr;
    Int16 i;

    if (*remain <= 0)
        return 0;

    /* Search for up to REMAIN bytes looking for the terminator. */
    for (i = 0; i < *remain && srcPtr[i]; i++)
        ;
    *len = i;

    if (i > 0) {
	h = MemHandleNew(i + 1);
	ErrFatalDisplayIf(!h, __FUNCTION__ ": out of memory");
	destPtr = MemHandleLock(h);
        ErrFatalDisplayIf(!destPtr, __FUNCTION__ ": out of memory");
        MemMove(destPtr, srcPtr, i);
	destPtr[i] = '\0';
	MemHandleUnlock(h);
	return h;
    } else {
	return 0;
    }
}


/*
 * PTR points to a pointer pointing to a buffer containing a string,
 * which runs on for no more than REMAIN bytes.  We copy out the first
 * NUL-terminated string, return it in a newly-allocated buffer, and
 * put its length in LEN.  PTR and REMAIN are adjusted to show
 * the amount remaining.
 */
MemHandle Mem_ReadString(Char **ptr, Int16 *remain, Int16 * len)
{
    MemHandle h;

    if (*remain <= 0) {
        FrmCustomAlert(ID_KeyDatabaseAlert,
                       "record underflow", __FUNCTION__, "");
        return NULL;
    }
    
    h = Mem_StrToHandle(*ptr, remain, len);

    *ptr += *len + 1;
    *remain -= *len + 1;
    
    return h;
}


void Mem_ReadChunk(Char * *ptr, UInt32 len, void * dest)
{
    MemMove(dest, *ptr, len);
    *ptr += len;
}


void Mem_CopyFromHandle(Char **dest, MemHandle h, UInt32 len)
{
    if (h) {
	Char * p = MemHandleLock(h);
	MemMove(*dest, p, len);
	*dest += len;
	MemHandleUnlock(h);
    } else {
	**dest = 0;
	*dest += 1;
    }
}
