/* -*- c-indentation-style: "k&r"; c-basic-offset: 4; indent-tabs-mode: nil; -*-
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


/* Sizes in bytes */
#define kDESBlockSize		8
#define kDES3BlockSize          16
#define kMD5HashSize            16

Err DES3_Buf(void * from, void * to, UInt32 len, Boolean encrypt,
	     UInt8 const *key);

void DES3_Write(void *recPtr, UInt32 off,
                char const *bodyBuf, UInt32 bodyLen);

