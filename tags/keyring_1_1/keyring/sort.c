/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 Martin Pool <mbp@users.sourceforge.net>
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
 * Because all records begin with the strz record name the comparison
 * is pretty simple: we sort in string order, except that deleted
 * records go to the end.  */
static Int16 Keys_Compare(void * rec1, void * rec2,
                          Int16 UNUSED(other),
                          SortRecordInfoPtr info1,
                          SortRecordInfoPtr info2,
                          MemHandle UNUSED(appInfoHand))
{
    Int16 result;
    Char	*cp1, *cp2;
    const Int16 attr1 = info1->attributes, attr2 = info2->attributes;

    if (attr1 & dmRecAttrSecret) {
         if (attr2 & dmRecAttrSecret)
              return 0;
         else
              return -1;
    } else {
         if (attr2 & dmRecAttrSecret)
              return +1;
    }

    if (attr1 & dmRecAttrDelete)
	result = +1;
    else if (attr2 & dmRecAttrDelete)
	result = -1;
    else {
	cp1 = (Char *) rec1;
	cp2 = (Char *) rec2;
	
	if (rec1  &&  !rec2)
	    result = -1;
	else if (!rec1  &&  rec2)
	    result = +1;
	else if (!rec1 && !rec2)
	    result = 0;
	else if (*cp1 && !*cp2)
	    result = -1;
	else if (!*cp1 && *cp2)
	    result = +1;
	else 
	    result = StrCompare(cp1, cp2);
    }
    return result;
}


/*
 * Sort the whole database.  Called on returning to the list after
 * modification.
 */
void Keys_Sort(void)
{
     Err err;

     err = DmInsertionSort(gKeyDB, Keys_Compare, 0);
     if (err) {
          UI_ReportSysError2(ID_SortError, err, __FUNCTION__);
     }
}
