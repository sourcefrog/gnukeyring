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

/* This file looks after generating random passwords on request. */

/* TODO: Save length and class settings for next time. */

#include <PalmOS.h>
#include <Password.h>
#include <Encrypt.h>

#include "resource.h"
#include "keyring.h"
#include "generate.h"
#include "uiutil.h"

enum includes {
    kLower = 1,
    kUpper = 2,
    kDigits = 4,
    kPunct = 8
};

static const Int16 lenMap[] = {
    4,	Length4Push,
    6,	Length6Push,
    8,	Length8Push,
    10,	Length10Push,
    16,	Length16Push,
    20,	Length20Push,
    -1
};

static const Int16 includeMap[] = {
    kLower, IncludeLower,
    kUpper, IncludeUpper,
    kDigits, IncludeDigits,
    kPunct, IncludePunct,
    -1
};


/* Return the user's saved preferences for password generation, or
 * otherwise the defaults. */
static void Generate_LoadOrDefault(Int16 * plen,
				   Int16 * pclasses) 
{
    Int16 data[2];
    const Int16 expectedSize = 2 * sizeof(Int16);
    Int16 size = expectedSize;
    Int16 gotSize;
    
    gotSize = PrefGetAppPreferences(kKeyringCreatorID,
				    kGeneratePref,
				    data,
				    &size,
				    true);
    if (gotSize == noPreferenceFound
	|| gotSize != expectedSize
	|| size != expectedSize) {
	*plen = 8;
	*pclasses = kLower;
    } else {
	*plen = data[0];
	*pclasses = data[1];
    }
}

	


/* Save the user's preference for password generation. */
static void Generate_Save(Int16 len, Int16 classes) {
    Int16 data[2] = {len, classes};

    PrefSetAppPreferences(kKeyringCreatorID,
			  kGeneratePref,
			  kAppVersion,
			  data,
			  2*sizeof(Int16),
			  true);
}


static void Generate_Init(FormPtr frm) {
    Int16 len, classes;
    
    Generate_LoadOrDefault(&len, &classes);

    UI_ScanAndSet(frm, lenMap, len);
    UI_UnionSet(frm, includeMap, classes);
}


static void Generate_Garbage(Char * ptr, Int16 flags, Int16 len) {
    Int16 	i;
    Char	ch;
    Int16		ri;

    for (i = 0; i < len; i++) {
	while (true) {
	    ri = SysRandom (0);
	    ch = (ri >> 8) ^ ri;
	    if (flags & kLower)
		if (ch >= 'a'  &&  ch <= 'z')
		    break;
	    if (flags & kUpper)
		if (ch >= 'A' && ch <= 'Z')
		    break;
	    if (flags & kDigits)
		if (ch >= '0' && ch <= '9')
		    break;
	    if (flags & kPunct)
		if ((ch >= '!' && ch <= '/')
		    || (ch >= ':' && ch <= '@')
		    || (ch >= '[' && ch <= '`')
		    || (ch >= '{' && ch <= '~'))
		    break;
	}
	
	ptr[i] = ch;
    }
    ptr[i] = 0;
}


static MemHandle Generate_MakePassword(FormPtr frm) {
    Int16		reqLength, reqFlags;
    MemHandle	h;
    Char *	ptr;

    reqLength = UI_ScanForFirst(frm, lenMap);
    if (reqLength <= 0  ||  reqLength > 2000) {
	// unreasonable or none
	return 0;
    }

    reqFlags = UI_ScanUnion(frm, includeMap);
    if (reqFlags == 0)
	return 0;

    Generate_Save(reqLength, reqFlags);

    h = MemHandleNew(reqLength + 1); // plus nul
    if (!h) {
	FrmAlert(OutOfMemoryAlert);
	return NULL;
    }
    
    ptr = MemHandleLock(h);
    Generate_Garbage(ptr, reqFlags, reqLength);

    MemHandleUnlock(h);
    return h;
}

MemHandle Generate_Run(void) {
    FormPtr 	prevFrm, frm;
    Int16		btn;
    MemHandle	result;

    prevFrm = FrmGetActiveForm();
    frm = FrmInitForm(GenerateForm);

    Generate_Init(frm);
    
    btn = FrmDoDialog(frm);

    if (btn == OkBtn) {
	result = Generate_MakePassword(frm);
    } else {
	result = 0;
    }

    FrmDeleteForm(frm);

    FrmSetActiveForm(prevFrm);

    return result;
}