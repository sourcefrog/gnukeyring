/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Tightly Bound -- store passwords securely on a handheld
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

void Keys_SaveRecord(UnpackedKeyType const *unpacked, UInt16 *idx);
void Key_SetCategory(UInt16 idx, UInt16 category);
Err KeyDB_CreateNew(UInt16 *idx);
void Keys_WriteRecord(UnpackedKeyType const *unpacked, void *recPtr,
		      UInt8 *key);

void Keys_CalcPackedSize(UnpackedKeyType const *unpacked);
