/* -*- c-indentation-style: "k&r"; c-basic-offset: 4 -*-
 * $Id$
 * 
 * Tightly Bound -- store passwords securely on a handheld
 * Copyright (C) 2000 Martin Pool <mbp@humbug.org.au>
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
#include "resource.h"
#include "category.h"
#include "uiutil.h"
#include "keydb.h"
#include "auto.h"

static Char		categoryName[dmCategoryLength];


/*
 * Update a popuptrigger to show a new category name.
 */
void Category_UpdateName(FormPtr frm, UInt16 category) {
    ControlPtr		ctl;

    /* TODO: Instead, cache this per form. */
    ctl = UI_GetObjectByID(frm, CategoryTrigger);
    CategoryGetName(gKeyDB, category, categoryName);
    CategorySetTriggerLabel(ctl, categoryName);
}


Boolean Category_Selected(Int16 *category, Boolean showAll) {
    FormPtr frm;
    Boolean		categoryEdited;
    Int16		oldCategory;

    oldCategory = *category;

    frm = FrmGetActiveForm();
    categoryEdited = CategorySelect(gKeyDB, frm,
				    CategoryTrigger,
				    CategoryList,
				    showAll, 
				    category,
				    categoryName,
				    1, 0);

    return (categoryEdited || *category != oldCategory);
}


