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

void KeyDB_SaveNewRecord(UnpackedKeyType const *unpacked, Char const *name);
void KeyDB_UpdateRecord(UnpackedKeyType const *unpacked, UInt idx);
void KeyDB_CreateAppInfo(void);
void KeyDB_SetPasswd(Char const *newPasswd);

Err KeyDB_OpenExistingDB(DmOpenRef *dbp);
Err KeyDB_CreateDB(DmOpenRef *dbp);
Err KeyDB_MarkForBackup(DmOpenRef dbp);

Boolean KeyDB_IsInitRequired(void);
Boolean KeyDB_Verify(Char const *guess);
void KeyDB_RepositionRecord(CharPtr name, UIntPtr idx);
#ifdef REALLY_OBLITERATE
void UnpackedKey_Obliterate(UnpackedKeyPtr u);
#endif /* REALLY_OBLITERATE */


void KeyRecord_Unpack(VoidHand record, UnpackedKeyType *u,
		      Byte const *key);
