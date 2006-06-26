/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2003-2005 by Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

#define kMD5HashSize            16
#define kMD5BlockSize           64

typedef struct MD5state_st
{
    UInt32 dig[4];
    UInt32 len,lenHi;
    UInt32 data[kMD5BlockSize/sizeof(UInt32)];
} MD5_CTX;

MD5_SECTION void 
MD5_Block (const UInt32 *digin, UInt32 *buffer, UInt32 *digout);
