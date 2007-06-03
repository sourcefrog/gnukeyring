/* -*- c-file-style: "java"; -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000, 2001 Martin Pool <mbp@users.sourceforge.net>
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

/* This file looks after generating random passwords on request. */

/*
 * TODO: Generate pronouncable text
 *
 * TODO: Prevent people from choosing no options.  To do that, I think
 * we would have to do a custom event loop, rather than calling
 * FrmDoDialog.  We may than also have a better hex handling, e.g.
 * doubling the length and disabling all other options.
 */

#include "includes.h"

enum includes {
    kLower = 1,
    kUpper = 2,
    kDigits = 4,
    kPunct = 8,
    kHigh = 16,
    kHex  = 64,
    kPronounceable = 32
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
    0, IncludeHigh,
    kHex, IncludeHex,
    kPronounceable, IncludeSyllables,
    -1
};

static const Int16 includeMapPalmLatin[] = {
    kLower, IncludeLower,
    kUpper, IncludeUpper,
    kDigits, IncludeDigits,
    kPunct, IncludePunct,
    kHigh, IncludeHigh,
    kHex, IncludeHex,
    kPronounceable, IncludeSyllables,
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

static void Generate_HexSelected(FormPtr frm, int selected)
{
    int i;
    static char lenLabels[(sizeof(lenMap)/sizeof(Int16) - 1)/2][3];

    for (i = 0; includeMap[i] != -1; i += 2) {
	if (includeMap[i] != kHex) {
	    UInt16 idx = FrmGetObjectIndex(frm, includeMap[i+1]);
	    if (selected) {
		FrmHideObject(frm, idx);
		CtlSetUsable(UI_GetObjectByID(frm, includeMap[i+1]), false);
	    } else {
		FrmShowObject(frm, idx);
	    }
	}
    }
    for (i = 0; lenMap[i] != -1; i += 2) {
	StrIToA(lenLabels[i/2], lenMap[i] * (selected ? 2 : 1));
	CtlSetLabel(UI_GetObjectByID(frm, lenMap[i+1]), lenLabels[i/2]);
    }
}


static void Generate_Init(FormPtr frm)
{
    GeneratePrefsType prefs;
    
    Generate_LoadOrDefault(&prefs);

    UI_ScanAndSet(frm, lenMap, prefs.len);
    UI_UnionSet(frm, includeMap, prefs.classes);
    Generate_HexSelected(frm, (prefs.classes & kHex) ? 1 : 0);
}


/*
 * FLAGS is a mask of allowed character classes from classMap.
 */
static void Generate_Hex(Char * ptr, Int16 len)
{
    Int16 	i;
    UInt8	ch;
    static const char hexchars[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    for (i = 0; i < len; i+=2) {
	ch = Secrand_GetByte();
	ptr[i  ] = hexchars[ch >> 4];
	ptr[i+1] = hexchars[ch & 0xf];
    }
    ptr[i] = 0;
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

/*
 * This is the routine that returns a random word.  Both word and
 * hyphenated_word must be pre-allocated. This algorithm was
 * initially worded out by Morrie Gasser in 1975.  Any changes here
 * are minimal so that as many word combinations can be produced as
 * possible (and thus keep the words random).  It collects random
 * syllables until a predetermined word length is found.
 *
 * http://www.eff.org//Privacy/Newin/New_nist/fips181.txt
 */
static void Generate_Word(Char * word, Int16 flags, Int16 pwlen)
{
    PronStateType state;
    Int16 word_length;
    Int16 oFlags = flags & (kDigits | kPunct);
    MemHandle pronHandle;
    void  *prondata;

    /*
     * Get rules and digram pointers.
     */
    pronHandle = DmGetResource('PRON', 1000);
    prondata = MemHandleLock(pronHandle);

    MemSet(&state, sizeof(state), 0);
    /*
     * The length of the word in characters.
     */
    word_length = 0;
    
    /*
     * Find syllables until the entire word is constructed.
     */
    while (word_length < pwlen)
    {
	/*
	 * Get the syllable and find its length.
	 */
	Char * syllable = word + word_length;
	Char * ptr;
	Pron_GetSyllable (syllable, pwlen - word_length, 
			  &state, prondata);
	word_length += StrLen (syllable);

	if ((flags & kUpper) != 0) {
	    /* Make some chars in syllable uppercase */
	    switch (Secrand_GetByte() & 3) {
	    case 0:
		/* lowercase */
		break;
	    case 1:
		/* uppercase */
		for (ptr = syllable; *ptr != 0; ptr++) {
		    *ptr -= 0x20;
		}
		break;
	    case 2:
		/* first character uppercase */
		syllable[0] -= 0x20;
		break;
	    case 3:
		/* vowels uppercase */
		for (ptr = syllable; *ptr != 0; ptr++) {
		    switch (*ptr) {
		    case 'y':
			/* y is not a vowel at the beginning */
			if (ptr == syllable)
			    break;
		    case 'a':
		    case 'e':
		    case 'i':
		    case 'o':
		    case 'u':
			*ptr -= 0x20;
		    }
		}
		break;
	    }
	}

	if (word_length < pwlen && oFlags != 0) {
	    Char ch;
	    do {
		ch = (Char) Secrand_GetByte();
	    } while (!(classMap[(UInt8) ch] & oFlags));
	    word[word_length++] = ch;
	}

	/* FIXME put the hyphenated syllables in the "notes" field?
	 */
    }

    word[word_length] = '\0';
    MemHandleUnlock(pronHandle);
    DmReleaseResource(pronHandle);
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

    if(prefs.classes & kHex)
	prefs.len *= 2;
    h = MemHandleNew(prefs.len + 1);
    if (!h) {
	FrmAlert(OutOfMemoryAlert);
	return NULL;
    }
    
    ptr = MemHandleLock(h);

    if(prefs.classes & kHex) {
	Generate_Hex(ptr, prefs.len);
    } else if(prefs.classes & kPronounceable) {
	Generate_Word(ptr, prefs.classes, prefs.len);
    } else {
	Generate_Garbage(ptr, prefs.classes, prefs.len);
    }

    MemHandleUnlock(h);
    return h;
}

static Boolean Generate_HandleEvent(EventPtr event)
{
    if (event->eType == ctlSelectEvent
	&& event->data.ctlSelect.controlID == IncludeHex) 
	Generate_HexSelected(FrmGetActiveForm(), event->data.ctlSelect.on);

    return false;
}

MemHandle Generate_Run(void)
{
    FormPtr 	prevFrm, frm;
    Int16	btn;
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
    FrmSetEventHandler(frm, Generate_HandleEvent);
    
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
