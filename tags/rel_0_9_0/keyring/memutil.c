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
#include "memutil.h"

#ifndef REALLY_OBLITERATE
#  define OBLIT_USED __attribute__((unused))
#endif /* !REALLY_OBLITERATE */

// ======================================================================
// Memory and database management routines

/* Scribble over all memory allocated to a handle.  It's OK to pass a null
 * handle */
void Mem_ObliterateHandle(MemHandle h OBLIT_USED) {
#if REALLY_OBLITERATE
    Char * ptr;

    if (!h)
	return;

    ptr = MemHandleLock(h);
    Mem_ObliteratePtr(ptr);
   
    MemHandleUnlock(h);
#endif /* REALLY_OBLITERATE */
}


void Mem_ObliteratePtr(void * ptr OBLIT_USED) {
#if REALLY_OBLITERATE
    UInt32 size = MemPtrSize(ptr);
    if (!size)
	return;
    MemSet(ptr, size-1, 'X');
    ((Char *) ptr)[size-1] = '\0';
#endif /* REALLY_OBLITERATE */
}


/* Return handle of a new chunk containing a copy of the string at
 * SRCPTR, and also put the length of that string in *LEN.  If the string
 * is "", then return null.  The returned length does not include the
 * terminal NUL, but the allocated chunk does have space for it. */
MemHandle Mem_StrToHandle(Char * srcPtr, UInt32 *len) {
    MemHandle h;
    void * destPtr;
    
    if ((*len = StrLen(srcPtr)) > 0) {    
	h = MemHandleNew(*len + 1);
	ErrFatalDisplayIf(!h, __FUNCTION__ ": out of memory");
	destPtr = MemHandleLock(h);
	StrCopy(destPtr, srcPtr);
	MemHandleUnlock(h);
	return h;
    } else {
	return 0;
    }
}


MemHandle Mem_ReadString(Char * *ptr, UInt32 * len) {
    MemHandle h;
    
    h = Mem_StrToHandle(*ptr, len);
    *ptr += *len + 1;
    return h;
}


void Mem_ReadChunk(Char * *ptr, UInt32 len, void * dest) {
    MemMove(dest, *ptr, len);
    *ptr += len;
}


void Mem_CopyFromHandle(Char * *dest, MemHandle h, UInt32 len)
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


UInt16 DB_ReadWord(Char * *ptr) {
    return *((UInt16 *) ptr)++;
}


UInt32 DB_ReadUInt32(Char * *ptr) {
    return *((UInt32 *) ptr)++;
}


/* Read a field value from *PTR, which is a pointer into a read-only
 * database record.  PTR advances over the read value.  If the string
 * is empty, the field keeps using it default buffer. */
void Mem_ReadStringIntoField(Char * *recPtr, FormPtr frm, UInt16 id) {
    MemHandle tmpHandle;
    UInt32 recLen;
    FieldPtr fld;
    
    tmpHandle = Mem_StrToHandle(*recPtr, &recLen);
    *recPtr += recLen + 1;
    fld = FrmGetObjectPtr(frm, FrmGetObjectIndex(frm, id));
    FldSetTextHandle(fld, (MemHandle) tmpHandle);
}
