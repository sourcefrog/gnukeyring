/* -*- c-basic-offset: 4; -*-
 *
 * $Id$
 * 
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@sourcefrog.net>
 *
 * You may use, modify, and redistribute this code without limitation
 * except that this copyright notice must be preserved.
 */

#include <stdio.h>

#include "hextype.h"


/*
 * Print out in a debugging form the LEN bytes of data starting at P.
 * Format is 16 bytes per line, with a little gap after the first
 * eight.  On the far left is the relative position, then the hex,
 * then the ascii characters if they are printable.
 */
void hextype(FILE *f, const void *p, size_t len)
{
    int               i, j;
    unsigned char const *d = (unsigned char const *) p;

    for (i = 0; i < len; ) {
	fprintf(f, "%4x: ", i);
	for (j = i; j < len && j < (i+16); j++) {
	    fprintf(f, "%02x ", d[j]);
	    if (j == i+7)
		fputs(": ", f);
	}
	for (; j < i+16; j++) {
	    fputs("   ", f);
	    if (j == i+7)
		fputs(": ", f);
	}
	fputs("  ", f);
	for (j = i; j < len && j < (i+16); j++) {
	    if (d[j] >= 0x20 && d[j] < 0x7f)
		fputc(d[j], f);
	    else
		fputc('.', f);
	    
	    if (j == i+7)
		fputc(' ', f);
	} 

	i = j;
	fputs("\n", f);
    }
}
