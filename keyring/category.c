/* -*- c-file-style: "java" -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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

static Char		categoryName[dmCategoryLength];

/*
 * At the moment we don't explicitly check for read-only databases,
 * because there seems no easy way to tell the Category Manager not to
 * display the Edit item.  We hope that it'll be smart enough to
 * notice the database is read only.
 */


/*
 * Update a popuptrigger to show a new category name.
 */
void Category_UpdateName(FormPtr frm, UInt16 category)
{
    ControlPtr		ctl;

    ctl = UI_GetObjectByID(frm, CategoryTrigger);
    CategoryGetName(gKeyDB, category, categoryName);
    CategorySetTriggerLabel(ctl, categoryName);
}

Boolean Category_Selected(Int16 *category, Boolean showAll)
{
    FormPtr frm;
    ListPtr lst;
    Boolean categoryEdited = false;
    Int16   oldCategory, newSelection;

    oldCategory = *category;

    frm = FrmGetActiveForm();
    lst = UI_GetObjectByID(frm, CategoryList);

    /* We can't simply use CategorySelect as we want to check for password. */

    CategoryCreateList (gKeyDB, lst, oldCategory, showAll, true, 1, 
			categoryDefaultEditCategoryString, true);
    newSelection = LstPopupList (lst);

    if (newSelection == LstGetNumberOfItems(lst) - 1) {
	if (Unlock_CheckKey()) {
	    categoryEdited = CategoryEdit(gKeyDB, category, 
					  categoryEditStrID, 1);
	    /* category may have been renamed */
	    Category_UpdateName(frm, *category);
	}
    } else if (newSelection != -1) {
	if (showAll && newSelection == 0)
	    *category = dmAllCategories;
	else
	    *category = CategoryFind
		(gKeyDB, LstGetSelectionText(lst, newSelection));
    }
    CategoryFreeList (gKeyDB, lst, showAll, categoryDefaultEditCategoryString);

    if (*category != oldCategory)
	categoryEdited = true;

    if (categoryEdited)
	Category_UpdateName(frm, *category);
    return categoryEdited;
}


Err KeyDB_CreateCategories(void)
{
    LocalID		appInfoID;
    MemHandle h;
    AppInfoPtr		appInfoPtr;

    if (DmDatabaseInfo(gKeyDBCardNo, gKeyDBID, 0, 0, 0, 0,
		       0, 0, 0,
		       &appInfoID, 0, 0, 0))
	return dmErrInvalidParam;

    if (appInfoID == 0) {
	h = DmNewHandle(gKeyDB, sizeof(AppInfoType));
	if (!h)
	    return DmGetLastErr();
                
	appInfoID = MemHandleToLocalID(h);
	DmSetDatabaseInfo(gKeyDBCardNo, gKeyDBID,
			  0,0,0,0,
			  0,0,0,
			  &appInfoID, 0,0,0);
    }
    appInfoPtr = MemLocalIDToLockedPtr(appInfoID, gKeyDBCardNo);

    /* Clear the app info block. */
    DmSet(appInfoPtr, 0, sizeof(AppInfoType), 0);

    /* Initialize the categories. */
    CategoryInitialize(appInfoPtr, CategoryRsrc);

    MemPtrUnlock(appInfoPtr);

    return 0;
}


