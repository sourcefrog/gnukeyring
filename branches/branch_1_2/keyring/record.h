/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2002 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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


// in-memory unpacked form of a key record
typedef struct {
    /* Length of corresponding string fields, not including the
     * terminating NUL that is present inside the memory blocks. */
    UInt16 nameLen, acctLen, passwdLen, notesLen;
    
    /* Handles to string values, or 0.
     *
     * It might be easier to keep pointers to locked-in strings here,
     * but the record is potentially too big to comfortably do that:
     * we might only have 16kB total of application dynamic RAM.
     * Also, the Field functions want to have handles they can resize,
     * rather than pointers. */
    MemHandle nameHandle, acctHandle, passwdHandle, notesHandle;

    UInt16 category;

    /* Date password was last changed. */
    DateType lastChange;
} UnpackedKeyType;

typedef UnpackedKeyType *UnpackedKeyPtr;
