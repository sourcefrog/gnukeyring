/* -*- c-file-style: "java"; -*-
 *
 * $Header$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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

/*
 * TODO: Generate pronouncable text
 *
 * TODO: Prevent people from choosing no options.  To do that, I think
 * we would have to do a custom event loop, rather than calling
 * FrmDoDialog.  */

#include "includes.h"

enum includes {
    kLower = 1,
    kUpper = 2,
    kDigits = 4,
    kPunct = 8,
    kHigh = 16
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

/**
 * Don't include high punctuation except if encoding is palm latin
 */
static const Int16 includeMapDefault[] = {
    kLower, IncludeLower,
    kUpper, IncludeUpper,
    kDigits, IncludeDigits,
    kPunct, IncludePunct,
    0, ID_IncludeHigh,
    -1
};

static const Int16 includeMapPalmLatin[] = {
    kLower, IncludeLower,
    kUpper, IncludeUpper,
    kDigits, IncludeDigits,
    kPunct, IncludePunct,
    kHigh, ID_IncludeHigh,
    -1
};

static const Int16 *includeMap;

/* Borrowed from linux/lib/ctype.c.  Thanks!  */
#define U	kUpper	/* upper */
#define L	kLower	/* lower */
#define D	kDigits	/* digit */
#define P	kPunct	/* punct */
#define H	kHigh   /* high but writable in Graffiti */

static const UInt8 classMap[256] = {
    0, 0, 0, 0, 0, 0, 0, 0,      /* 0-7 */
    0, 0, 0, 0, 0, 0, 0, 0,      /* 8-15 */
    0, 0, 0, 0, 0, 0, 0, 0,      /* 16-23 */
    0, 0, 0, 0, 0, 0, 0, 0,      /* 24-31 */
    0, P, P, P, P, P, P, P,      /* 32-39 */
    P, P, P, P, P, P, P, P,      /* 40-47 */
    D, D, D, D, D, D, D, D, /* 48-55 */
    D, D, P, P, P, P, P, P, /* 56-63 */
    P, U, U, U, U, U, U, U, /* 64-71 */
    U, U, U, U, U, U, U, U, /* 72-79 */
    U, U, U, U, U, U, U, U, /* 80-87 */
    U, U, U, P, P, P, P, P, /* 88-95 */
    P, L, L, L, L, L, L, L, /* 96-103 */
    L, L, L, L, L, L, L, L, /* 104-111 */
    L, L, L, L, L, L, L, L, /* 112-119 */
    L, L, L, P, P, P, P, 0,     /* 120-127 */
    0, 0, 0, 0, 0, 0, 0, 0,      /* 128-135 */
    0, 0, 0, 0, 0, 0, 0, 0,      /* 136-143 */
    0, H, H, H, H, H, 0, 0,      /* 144-151 */
    H, H, 0, 0, 0, 0, 0, H,      /* 152-159 */
    H, H, H, H, 0, H, 0, H,      /* 160-167 */
    0, H, 0, 0, 0, 0, H, 0,      /* 168-175 */
    H, H, 0, 0, 0, 0, 0, 0,      /* 176-183 */
    0, 0, 0, 0, 0, 0, 0, H,      /* 184-191 */
    H, H, H, H, H, H, H, H,      /* 192-199 */
    H, H, H, H, H, H, H, H,      /* 200-207 */
    0, H, H, H, H, H, H, H,      /* 208-215 */
    H, H, H, H, H, H, 0, 0,      /* 216-223 */
    H, H, H, H, H, H, H, H,      /* 224-231 */
    H, H, H, H, H, H, H, H,      /* 232-239 */
    0, H, H, H, H, H, H, H,      /* 240-247 */
    H, H, H, H, H, H, 0, H       /* 248-255 */
};

#undef U
#undef L
#undef P
#undef H


typedef struct {
    Int16 len;
    Int16 classes;
} GeneratePrefsType;
typedef GeneratePrefsType *GeneratePrefsPtr;


/* Return the user's saved preferences for password generation, or
 * otherwise the defaults. */
static void Generate_LoadOrDefault(GeneratePrefsPtr prefs)
{
    Int16 size = sizeof *prefs;

    prefs->len = 8;
    prefs->classes = kLower;
    
    PrefGetAppPreferences(kKeyringCreatorID,
			  kGeneratePref,
			  prefs,
			  &size,
			  true);
}

	


/* Save the user's preference for password generation. */
static void Generate_Save(GeneratePrefsPtr prefs)
{
    PrefSetAppPreferences(kKeyringCreatorID,
			  kGeneratePref,
			  kAppVersion,
			  prefs,
			  sizeof *prefs,
			  true);
}


static void Generate_Init(FormPtr frm)
{
    GeneratePrefsType prefs;
    
    Generate_LoadOrDefault(&prefs);

    UI_ScanAndSet(frm, lenMap, prefs.len);
    UI_UnionSet(frm, includeMap, prefs.classes);
}


/*
 * FLAGS is a mask of allowed character classes from classMap.
 */
static void Generate_Garbage(Char * ptr, Int16 flags, Int16 len)
{
    Int16 	i;
    Char	ch;

    for (i = 0; i < len; i++) {
        /* We used to first choose a class of character, but that
         * tends to generate too many digits.  So instead we pick any
         * character and see if it's included.  */
        
        do {
            ch = (Char) Secrand_GetByte();
        } while (!(classMap[(UInt8) ch] & flags));
	
	ptr[i] = ch;
    }
    ptr[i] = 0;
}


static MemHandle Generate_MakePassword(FormPtr frm)
{
    GeneratePrefsType prefs;
    MemHandle	h;
    Char *	ptr;

    prefs.len = UI_ScanForFirst(frm, lenMap);
    if (prefs.len <= 0  ||  prefs.len > 2000) {
	// unreasonable or none
	return 0;
    }

    prefs.classes = UI_ScanUnion(frm, includeMap);
    if (prefs.classes == 0)
	return 0;

    Generate_Save(&prefs);

    h = MemHandleNew(prefs.len + 1); // plus nul
    if (!h) {
	FrmAlert(OutOfMemoryAlert);
	return NULL;
    }
    
    ptr = MemHandleLock(h);
    Generate_Garbage(ptr, prefs.classes, prefs.len);

    MemHandleUnlock(h);
    return h;
}


MemHandle Generate_Run(void)
{
    FormPtr 	prevFrm, frm;
    Int16		btn;
    MemHandle	result;
    UInt32      encoding;

    if (FtrGet(sysFtrCreator, sysFtrNumEncoding, &encoding))
	/* if feature not found it is palm latin */
	encoding = charEncodingPalmLatin;
    if (encoding == charEncodingPalmLatin)
	includeMap = includeMapPalmLatin;
    else
	includeMap = includeMapDefault;

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
