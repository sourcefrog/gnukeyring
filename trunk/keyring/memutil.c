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

#include <Pilot.h>
#include <Password.h>
#include <Encrypt.h>

#include "keyring.h"
#include "memutil.h"
#include "callback.h"

#ifndef REALLY_OBLITERATE
#  define OBLIT_USED __attribute__((unused))
#endif /* !REALLY_OBLITERATE */

// ======================================================================
// Memory management routines

/* Scribble over all memory allocated to a handle.  It's OK to pass a null
 * handle */
void Mem_ObliterateHandle(VoidHand h OBLIT_USED) {
#if REALLY_OBLITERATE
    CharPtr ptr;

    if (!h)
	return;

    ptr = MemHandleLock(h);
    Mem_ObliteratePtr(ptr);
   
    MemHandleUnlock(h);
#endif /* REALLY_OBLITERATE */
}


void Mem_ObliteratePtr(VoidPtr ptr OBLIT_USED) {
#if REALLY_OBLITERATE
    ULong size = MemPtrSize(ptr);
    if (!size)
	return;
    MemSet(ptr, size-1, 'X');
    ((CharPtr) ptr)[size-1] = '\0';
#endif /* REALLY_OBLITERATE */
}


/* Return handle of a new chunk containing a copy of the string at
 * SRCPTR, and also put the length of that string in *LEN.  If the string
 * is "", then return null.  The returned length does not include the
 * terminal NUL, but the allocated chunk does have space for it. */
VoidHand Mem_StrToHandle(CharPtr srcPtr, ULong *len) {
    VoidHand h;
    VoidPtr destPtr;
    
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


VoidHand Mem_ReadString(CharPtr *ptr, ULongPtr len) {
    VoidHand h;
    
    h = Mem_StrToHandle(*ptr, len);
    *ptr += *len + 1;
    return h;
}


void Mem_ReadChunk(CharPtr *ptr, ULong len, VoidPtr dest) {
    MemMove(dest, *ptr, len);
    *ptr += len;
}


void DB_WriteStringFromHandle(CharPtr dest, ULong *off, VoidHand h, ULong len) {
    if (h) {
	CharPtr p = MemHandleLock(h);
	DmWrite(dest, *off, p, len);
	*off += len;
	MemHandleUnlock(h);
    } else {
	DmWrite(dest, *off, "", 1);
	(*off)++;
    }
}


void Mem_CopyFromHandle(CharPtr *dest, VoidHand h, ULong len)
{
    if (h) {
	CharPtr p = MemHandleLock(h);
	MemMove(*dest, p, len);
	*dest += len;
	MemHandleUnlock(h);
    } else {
	**dest = 0;
	*dest += 1;
    }
}


Word DB_ReadWord(CharPtr *ptr) {
    return *((Word *) ptr)++;
}


ULong DB_ReadULong(CharPtr *ptr) {
    return *((ULong *) ptr)++;
}


/* Read a field value from *PTR, which is a pointer into a read-only
 * database record.  PTR advances over the read value.  If the string
 * is empty, the field keeps using it default buffer. */
void Mem_ReadStringIntoField(CharPtr *recPtr, FormPtr frm, Word id) {
    VoidHand tmpHandle;
    ULong recLen;
    FieldPtr fld;
    
    tmpHandle = Mem_StrToHandle(*recPtr, &recLen);
    *recPtr += recLen + 1;
    fld = FrmGetObjectPtr(frm, FrmGetObjectIndex(frm, id));
    FldSetTextHandle(fld, (Handle) tmpHandle);
}
