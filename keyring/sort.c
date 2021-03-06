/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2002-2003 Jochen Hoenicke <hoenicke@users.sourceforge.net>
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

/*
 * Alphanumeric sorting of records.
 *
 * Perhaps the best sort order (not implemented yet) would be:
 * reserved records (fixed positions), records with no name in order
 * of insertion by database index, normal records sorted by name and
 * then by database index, and finally deleted records.  I think we'll
 * try just always inserting into the right position and never
 * explicitly inserting.
 *
 * We must make sure never to move the reserved records, and also that
 * things are stable whichever category we sort.
 */


/* Compare records for sorting or sorted insertion.
 *
 * Because all records begin with the field containing the record name
 * the comparison is pretty simple: we sort in string order, except
 * that deleted records go to the end.  
 */
static Int16 Keys_Compare(void * rec1, void * rec2,
                          Int16 UNUSED(other),
                          SortRecordInfoPtr info1,
                          SortRecordInfoPtr info2,
                          MemHandle UNUSED(appInfoHand))
{
    Int16 result;
    FieldHeaderType *fd1, *fd2;
    Char  *cp1, *cp2;
    const Int16 attr1 = info1->attributes, attr2 = info2->attributes;
    
    if (attr1 & dmRecAttrSecret) {
	if (attr2 & dmRecAttrSecret)
	    result = 0;
	else
	    result = -1;
    } else if (attr2 & dmRecAttrSecret) {
	result = +1;

    } else if (!rec1) {
	if (!rec2)
	    result = 0;
	else
	    result = -1;
    } else if (!rec2) {
	result = +1;
    } else {
	fd1 = (FieldHeaderType *) rec1;
	fd2 = (FieldHeaderType *) rec2;
	cp1 = (Char *) (fd1+1);
	cp2 = (Char *) (fd2+1);
	result = TxtGlueCaselessCompare(cp1, fd1->len, NULL, 
					cp2, fd2->len, NULL);
    }
    if (!result)
	result = MemCmp(info1->uniqueID, info2->uniqueID, 3);
    return result;
}


/*
 * Sort the whole database.  Called on returning to the list after
 * modification.
 */
void Keys_Sort(void)
{
     Err err;

     /* Insertion sort is actually much faster than quick sort
      * in the common case (where most records are already in order).
      */
     err = DmInsertionSort(gKeyDB, Keys_Compare, 0);
     if (err) {
          UI_ReportSysError2(SortErrorAlert, err, __FUNCTION__);
     }
}
