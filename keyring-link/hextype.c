/* -*- c-basic-offset: 4; -*-
 *
 * $Id$
 * 
 * GNU Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@sourcefrog.net>
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

#include <stdio.h>
#include <ctype.h>

#include "hextype.h"


void hextype(FILE *f, unsigned char const *d, size_t len)
{
    int               i, j;

    for (i = 0; i < len; ) {
	fprintf(f, "%4x: ", i);
	for (j = i; j < len && j < (i+16); j++) {
	    fprintf(f, "%02x ", d[j]);
	    if (j == i+7)
		fputs(": ", f);
	}
	for (; j < i+16; j++) {
	    fprintf(f, "   ");
	    if (j == i+7)
		fputs(": ", f);
	}
	printf("  ");
	for (j = i; j < len && j < (i+16); j++) {
	    if (d[j] >= 0x20 && d[j] < 0x7f)
		fputc(d[j], f);
	    else
		fputc('.', f);
	    
	    if (j == i+7)
		fputc(' ', f);
	} 

	i = j;
	if (i != (len-1))
	    fprintf(f, "\n");
    }
    fprintf(f, "\n");
}
