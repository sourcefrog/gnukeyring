/* -*- c-file-style: "k&r"; -*- 
 *
 * $Id$
 * 
 * GNU Keyring -- store passwords securely on a handheld
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

extern Int16 gKeyDBCardNo;
extern LocalID gKeyDBID;
extern DmOpenRef gKeyDB;


#define kMasterHashRec 0
#define kNumHiddenRecs 1

Err KeyDB_CreateCategories(void);

Err KeyDB_CreateRingInfo(void);
void KeyDB_SetPasswd(Char *newPasswd);

Err KeyDB_OpenExistingDB(void);
Err KeyDB_CreateDB(void);
Err KeyDB_MarkForBackup(void);
Err KeyDB_GetVersion(UInt16 *ver);
Err KeyDB_SetVersion(void);


enum KeyDB_State KeyDB_Examine(void);
Boolean KeyDB_Verify(Char const *guess);

Int16 Keys_IdxOffsetReserved(void);
Err KeyDB_CreateReservedRecords(void);


extern Boolean g_ReadOnly;
     
Err KeyDB_Init(void);
