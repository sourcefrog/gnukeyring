/* -*- c-file-style: "k&r"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@humbug.org.au>
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

void * UI_GetObjectByID(FormPtr frm, UInt16 objectID);
void * UI_ObjectFromActiveForm(UInt16 objectID);
FieldPtr UI_GetFocusObjectPtr(void);

int UI_ScanForFirst(FormPtr frm, UInt16 const * map);
void UI_ScanAndSet(FormPtr frm, UInt16 const *map, UInt16 value);
void UI_SelectCategory(void);

int UI_ScanUnion(FormPtr frm, UInt16 const * map);
void UI_UnionSet(FormPtr frm, UInt16 const *map, UInt16 value);

void UI_UpdateCategoryName(FormPtr frm, UInt16 category);

void UI_ReportSysError2(UInt16 msgID, Err err, char const *where);

void App_NotImplemented(void);
Boolean App_CheckReadOnly(void);
